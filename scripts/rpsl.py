#!/usr/bin/python
#
# BGPcrunch - BGP analysis toolset
# (C) 2014-2015 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import re
import sys
import os
import traceback
import threading

import common
import graph
import ianaspace
import bgp

# Constants

MY_ASN=None # or 'AS29134'

MAX_THREADS=3

RIPE_DB_ROUTE='/ripe.db.route'
RIPE_DB_ROUTE6='/ripe.db.route6'
RIPE_DB_AUTNUM='/ripe.db.aut-num'
RIPE_DB_ASSET='/ripe.db.as-set'
RIPE_DB_FILTERSET='/ripe.db.filter-set'
RIPE_DB_ROUTESET='/ripe.db.route-set'

RIPE_DB_ROUTE_PICKLE='/ripe.route.pickle'
RIPE_DB_ROUTE6_PICKLE='/ripe.route6.pickle'
RIPE_DB_AUTNUM_PICKLE='/ripe.autnum.pickle'
RIPE_DB_ASSET_PICKLE='/ripe.asset.pickle'
RIPE_DB_FILTERSET_PICKLE='/ripe.filterset.pickle'
RIPE_DB_ROUTESET_PICKLE='/ripe.routeset.pickle'

RIPE_BGP2ROUTES4_TXT='/bgp2routes.txt'
RIPE_BGP2ROUTES4_PICKLE='/bgp2routes.pickle'
RIPE_BGP2ROUTES6_TXT='/bgp2routes.txt'
RIPE_BGP2ROUTES6_PICKLE='/bgp2routes.pickle'

RIPE_BGP2PATHS4_TXT='/bgp2paths.txt'
RIPE_BGP2PATHS4_PICKLE='/bgp2paths.pickle'
RIPE_BGP2PATHS6_TXT='/bgp2paths6.txt'
RIPE_BGP2PATHS6_PICKLE='/bgp2paths6.pickle'

RIPE_ROUTE_VIOLATION_TIMELINE='/route_violations_timeline.txt'
RIPE_ROUTE6_VIOLATION_TIMELINE='/route6_violations_timeline.txt'


# Data model

class RpslObject(object):
    def __init__(self,textlines):
        self.text=textlines

    def __repr__(self):
        return self.__str__()

    def getKey(self):
        """
        Returns key value that should correspond to the object key in RPSL standard view.
        It is here for common HashObjectDirectory to use it for constructing lookup table.
        """
        raise Exception("This is abstract object. Dunno what my key is!")

    
    @staticmethod
    def cleanupLines(text):
        for l in text:           
            # Discard comments
            c = l.find('#')
            if c > -1:
                l = l[:c]

            # Discard empty lines
            if len(l.strip()) == 0:
                continue

            # Discard RIPE DB comments
            if l[0] == '%':
                continue

            yield l.upper()
        
    
    @staticmethod
    def splitLines(text):
        """ Returns generator of tuples (attribute,value) and discards comments. """

        buf=('','')
        for l in text:           
            if buf[0]:
                if l[0].isspace() or l[0]=='+':
                    buf=(buf[0],str(buf[1]+' '+l[1:].strip()).strip())
                    continue
                else:
                    yield buf

            # Find attr and value
            gr=l.strip().split(':',1)
            if len(gr) != 2:
                raise Exception("Can not parse line: "+l)

            buf=(gr[0].strip(), gr[1].strip())

        if len(buf[0].strip())>0:
            yield buf

    @staticmethod    
    def parseRipeFile(filename, targetClass):
        """ Parse RIPE object file of a targetClass. Theoretically more
        types might be  supported and modifier to __init__ of each class
        has to be created. """
        def flushrobj(ot):
            if ot:
                otl = list(RpslObject.cleanupLines(ot))
                if otl:
                    return targetClass(otl)
    
        with open(filename, 'r') as sf:
            objecttext=[]
            for l in sf.readlines():
                if l.strip()=='':
                    o=flushrobj(objecttext)
                    if o:
                        yield o
                
                    objecttext=[]
                else:
                    objecttext.append(l)

            # last one
            o=flushrobj(objecttext)
            if o:
                yield o





# Route object machinery

class RouteObject(RpslObject):
    """ Internal representation of route RPSL object. """
    
    ROUTE_ATTR = 'ROUTE'
    ORIGIN_ATTR = 'ORIGIN'
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.route=None
        self.origin=None

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.ROUTE_ATTR:
                self.route=v.strip()
            elif a==self.ORIGIN_ATTR:
                if v.upper()[:2] == 'AS':
                    self.origin=v.strip().upper()
                else:
                    raise Exception("Can not parse tuple "+a+":"+v)

            # TODO???: Add holes. But why? It is impossible to check hole existence at
            # this point. New module and new walk through is needed perhaps.

            if self.route and self.origin:
                break

        if not (self.route and self.origin):
            raise Exception("Can not create RouteObject out of text: "+str(textlines))

    def getKey(self):
        return self.route.upper()

    def __str__(self):
        return 'RouteObject: '+str(self.route)+'->'+str(self.origin)


class Route6Object(RouteObject):
    """ Internal representation of route6 RPSL object. """

    # inherit route object and change ongly the key attribute indicator
    ROUTE_ATTR='ROUTE6'



class RouteObjectDir(object):
    """
    Special directory for route and route6 objects. Fast IP address lookup
    support is needed here as well as support for route/route6 object semantics
    binding one route to multiple origin ASes as well as having a collection of
    multiple routes for one AS. Lookups are possible in both direction using
    IPLookupTree in one (IP prefix -> list of route objects) and hash table in the
    other (origin -> list of route objects).
    """

    def __init__(self,filename,ipv6=False):
        self.originTable={}
        if ipv6:
            self._initTreeAndTable(RpslObject.parseRipeFile(filename, Route6Object), ipv6)
        else:
            self._initTreeAndTable(RpslObject.parseRipeFile(filename, RouteObject), ipv6)

    def _initTreeAndTable(self,routeobjects,ipv6):
        """ routeobjects is supposedly a generator... """
        self.tree=common.IPLookupTree(ipv6)
        for o in routeobjects:
            self.tree.add(o.route,o)
            if not o.origin in self.originTable:
                self.originTable[o.origin]=[]
            self.originTable[o.origin].append(o)


    def getRouteObjs(self, prefix):
        return self.tree.lookupNetExact(prefix)






# Aut-num object machinery

EXPRESSION_DECODE=re.compile('^([^\{\}]{5,}.*|\{(.+)\}(\s+REFINE .*|\s+EXCEPT .*)?)$')
FACTOR_SPLIT_ACCEPT='ACCEPT '
FACTOR_SPLIT_ANNOUNCE='ANNOUNCE '
FACTOR_SPLIT_NETWORKS='NETWORKS '
FACTOR_SPLIT_FROM='FROM '
FACTOR_SPLIT_TO='TO '
AFI_MATCH=re.compile('^AFI\s+([^\s]+)\s+(.*)$')

IMPORT_FACTOR_MATCH=re.compile('^FROM\s+([^\s]+)(\s+(.*)?\s?ACCEPT(.+))?$')
EXPORT_FACTOR_MATCH=re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?ANNOUNCE(.+))?$')
DEFAULT_FACTOR_MATCH=re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?NETWORKS(.+)|.*)?$')
class AutNumRule(object):
    """ Abstract base for internal representation of a rule in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """

        self.mp = mp
        self.text = line.upper()

    def __str__(self):
        return "%s%s : %s"%(self.__class__.__name__, (' MP' if self.mp else ''), self.text)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def _decomposeExpression(text):
        # split line to { factor1; factor2; ... } and the rest (refinements etc)
        m=EXPRESSION_DECODE.match(text)

        if m:
            e=None
            # ignore refinements and excepts and count on case insensitivity of RPSL
            if m.group(1):
                e=m.group(1).strip()
            elif m.group(0):
                e=m.group(0).strip()
            else:
                raise Exception('Can not find needed groups in split of expression: '+text)

            # defaults for rules like: export: default to AS1234
            sel=e
            fltr=''
            if e.find(FACTOR_SPLIT_ACCEPT)>-1:
                [sel,fltr] = e.split(FACTOR_SPLIT_ACCEPT, 1)
                fltr=(FACTOR_SPLIT_ACCEPT+fltr).strip()
            elif e.find(FACTOR_SPLIT_ANNOUNCE)>-1:
                [sel,fltr] = e.split(FACTOR_SPLIT_ANNOUNCE, 1)
                fltr=(FACTOR_SPLIT_ANNOUNCE+fltr).strip()
            elif e.find(FACTOR_SPLIT_NETWORKS)>-1:
                [sel,fltr] = e.split(FACTOR_SPLIT_NETWORKS, 1)
                fltr=(FACTOR_SPLIT_NETWORKS+fltr).strip()
            else:
                common.w("Syntax error: Can not find selectors in:", e)
                #raise Exception("Can not find selectors in: "+e)

            if sel.find(FACTOR_SPLIT_FROM)>-1:
                return ([str(FACTOR_SPLIT_FROM+f).strip() for f in sel.split(FACTOR_SPLIT_FROM)[1:]], fltr)

            elif sel.find(FACTOR_SPLIT_TO)>-1:
                return ([str(FACTOR_SPLIT_TO+f).strip() for f in sel.split(FACTOR_SPLIT_TO)[1:]], fltr)
            
            else:
                raise Exception("Can not find filter factors in: "+sel)
                
        else:
            raise Exception("Can not split expression: "+text)

    @staticmethod
    def _normalizeFactor(selector, fltr):
        """
        Returns (subject, filter) where subject is AS or AS-SET and
        filter is a filter. For example in factor:
        "to AS1234 announce AS-SECRETNET" : the subject is AS1234 and
        the filter is the AS-SECRETNET; the same for factor:
        "from AS1234 accept ANY": the subject is AS1234 and the filter
        is ANY and the same for default factors like the following:
        "to AS1234 networks ANY"
        """

        factor=(selector+' '+fltr).strip()
        if factor[-1] == ';':
            factor=factor[:-1].strip()

        m=IMPORT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),(m.group(4).strip() if m.group(4) else 'ANY'))

        m=EXPORT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),(m.group(4).strip() if m.group(4) else 'ANY'))

        m=DEFAULT_FACTOR_MATCH.match(factor)
        if m and m.group(1):
            return (m.group(1).strip(),(m.group(4).strip() if m.group(4) else 'ANY'))

        raise Exception("Can not parse factor: "+factor)


    def _parseRule(self):
        """
        Returns (afi, [(subject, filter)]). Remove all refine and except blocks
        as well as protocol and to specs.

        The (subject, filter) are taken from factors where subject is
        AS or AS-SET and filter is a filter string. For example in factor:
        "to AS1234 announce AS-SECRETNET" : the subject is AS1234 and
        the filter is the AS-SECRETNET; the same for factor:
        "from AS1234 accept ANY": the subject is AS1234 and the filter
        is ANY.

        afi is by default ipv4.unicast. For MP rules it is being parsed and
        filled in according to the rule content.
        """

        afi='IPV4.UNICAST'
        if self.mp:
            r=AFI_MATCH.match(self.text)
            if r:
                afi=r.group(1)
                e=r.group(1)
            else:
                afi='ANY'

        factors=AutNumRule._decomposeExpression(self.text)

        return (afi,[AutNumRule._normalizeFactor(f, factors[1]) for f in factors[0]])



    @staticmethod
    def matchFilter(factor, prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6=False):
        # TODO
        return True


    def match(self, subject, prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6=False):
        """
        Interpret the rule and decide whether a prefix should be accepted or not.

        subject = AS that is announcing the prefix to or as that the prefix is exported to by
        the AS that conains this rule
        prefix = prefix that is in question
        currentAsPath = aspath as it is (most likely) seen by the AS
        assetDirectory = HashObjectDir that conains the AsSetObjects
        fltrsetDirectory = HashObjectDir that conains the FilterSetObjects
        rtsetDirectory = HashObjectDir that conains the RouteSetObjects
        ipv6 = matching IPv6 route?
        """

        def isASN(asn):
            return str(asn).upper()[:2] == 'AS'

        # Fast-path, fail for IPv6 with non-MP rule
        # This is problematic... A lot of people does not have proper
        # routing politics written with mp-* rules and people
        # just freely intepret the aut-num objects as being multi-protocol
        # by default. (Which is not true...)
        if (not self.mp) and ipv6:
            return False

        res=self._parseRule() # (afi, [(subject, filter)])

        # Check address family matches
        if res[0] != 'ANY' and res[0] != 'ANY.UNICAST':
            if ((ipv6 and res[0] != 'IPV6.UNICAST') or
            ((not ipv6) and res[0] != 'IPV4.UNICAST')):
                return False

        # Walk through factors and find whether there is subject match,
        # run the filter if so
        for f in res[1]:
            #common.d("Match? sub=", subject, 'f=', str(f))

            if isASN(f[0]):
                if f[0] == subject:
                    return self.matchFilter(f[1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6)

            elif AsSetObject.isAsSet(f[0]):
                if f[0] in assetDirectory.table:
                    if assetDirectory.table[f[0]].matchRecursive(subject.upper()):
                        return self.matchFilter(f[1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6)

            else:
                #raise Exception("Can not expand subject: "+str(f[0]))
                common.w("Can not expand subject:", str(f[0]))
                return False

        # No match of factor means that the prefix should not appear
        return False

    

class AutNumImportRule(AutNumRule):
    """ Internal representation of a rule (=import, mp-import line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRule.__init__(self, line, mp)



class AutNumDefaultRule(AutNumRule):
    """ Internal representation of a default rule (=default, mp-default line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRule.__init__(self, line, mp)




class AutNumExportRule(AutNumRule):
    """ Internal representation of a rule (=export, or mp-export line)
    in an aut-num object.
    """

    def __init__(self, line, mp=False):
        """
        line = the rule text (value)
        mp = mutli-protocol rule (according RFC 4012)
        """
        AutNumRule.__init__(self, line, mp)

############################################




class AutNumObject(RpslObject):
    """ Internal representation of aut-num RPSL object. """
    
    AUTNUM_ATTR='AUT-NUM'
    IMPORT_ATTR='IMPORT'
    EXPORT_ATTR='EXPORT'
    MP_IMPORT_ATTR='MP-IMPORT'
    MP_EXPORT_ATTR='MP-EXPORT'
    DEFAULT_ATTR="DEFAULT"
    MP_DEFAULT_ATTR="MP-DEFAULT"
    
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.aut_num=None
        self.import_list=[]
        self.export_list=[]
        self.mp_import_list=[]
        self.mp_export_list=[]

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.AUTNUM_ATTR:
                if v.upper()[0:2] == 'AS':
                    self.aut_num=v.strip().upper()
                else:
                    raise Exception('Can not parse aut-num line: '+str((a,v)))
            elif a==self.IMPORT_ATTR:
                self.import_list.append(AutNumImportRule(v))

            elif a==self.DEFAULT_ATTR:
                self.import_list.append(AutNumDefaultRule(v))

            elif a==self.EXPORT_ATTR:
                self.export_list.append(AutNumExportRule(v))

            elif a==self.MP_IMPORT_ATTR:
                self.mp_import_list.append(AutNumImportRule(v, True))

            elif a==self.MP_DEFAULT_ATTR:
                self.mp_import_list.append(AutNumDefaultRule(v, True))

            elif a==self.MP_EXPORT_ATTR:
                self.mp_export_list.append(AutNumExportRule(v, True))
                
            else:
                pass # ignore unrecognized lines

        if self.aut_num == None:
            raise Exception("Can not create AutNumObject out of text: "+str(textlines))


    def getKey(self):
        return self.aut_num


    def __str__(self):
        return '''AutNumObject: %s
import: %s
export: %s
mp-import: %s
mp-export: %s
-----------------
'''%(self.aut_num, self.import_list, self.export_list, self.mp_import_list,
     self.mp_export_list)






# Set-* objects

class AsSetObject(RpslObject):
    """ Internal representation of as-set RPSL object. """

    ASSET_ATTR='AS-SET'
    MEMBERS_ATTR='MEMBERS'

    @staticmethod
    def _parseMembers(members):
        for m in members.strip().split(','):
            yield m.strip().upper()

    @staticmethod
    def isAsSet(name):
        """ Returs True when the name appears to be as-set name (=key)
        according to RPSL specs. """
        return str(name).upper().find('AS-') > -1
    
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.as_set=None
        self.members=[]

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.ASSET_ATTR:
                self.as_set=v.strip().upper()
                
            elif a==self.MEMBERS_ATTR:
                # flatten the list in case we have this:
                # members: AS123, AS456, AS-SOMETHING
                # members: AS234, AS-SMTHNG
                for m in AsSetObject._parseMembers(v):
                    self.members.append(m)

            else:
                pass # ignore unrecognized lines

        if not self.as_set:
            raise Exception("Can not create AsSetObject out of text: "+str(textlines))


    def getKey(self):
        return self.as_set

    def recursiveMatch(self, target, hashObjDir, recursionList=[]):
        # prevent recusion loop
        if self.getKey() in recursionList:
            return False
        recursionList.append(self.getKey())
        
        if target in self.members:
            return True

        for m in members:
            if isAsSet(m) and m in hashObjDir.table:
                r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
                if r:
                    return True

        return False

    def __str__(self):
        return 'AsSetbject: %s -< %s'%(self.as_set, str(self.members))




class FilterSetObject(RpslObject):
    """ Internal representation of filter-set RPSL object. """

    FILTERSET_ATTR='FILTER-SET'
    FILTER_ATTR='FILTER'
    MP_FILTER_ATTR="MP-FILTER"

    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.filter_set=None
        self.filter=None
        self.mp_filter=None

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.FILTERSET_ATTR:
                self.filter_set=v.strip().upper()
                
            elif a==self.FILTER_ATTR:
                self.filter=v.strip()

            elif a==self.MP_FILTER_ATTR:
                self.mp_filter=v.strip()

            else:
                pass # ignore unrecognized lines

        if not self.filter_set:
            raise Exception("Can not create FilterSetObject out of text: "+str(textlines))


    def getKey(self):
        return self.filter_set

    def __str__(self):
        f=None
        if self.filter:
            f=str(self.filter)
        if self.mp_filter:
            if f:
                f+=' + '
            else:
                f=''
            f+=str(self.mp_filter)
        return 'FilterSetbject: %s -< %s'%(self.filter_set, f)

    def match(self, prefix, originAS):
        # TODO
        return True

class RouteSetObject(RpslObject):
    """ Internal representation of route-set RPSL object. """

    ROUTESET_ATTR='ROUTE-SET'
    MEMBERS_ATTR='MEMBERS'
    MP_MEMBERS_ATTR="MP-MEMBERS"

    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.route_set=None
        self.members=[]
        self.mp_members=[]

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.ROUTESET_ATTR:
                self.route_set=v.strip().upper()
                
            elif a==self.MEMBERS_ATTR:
                self.members.append(v.strip().upper())

            elif a==self.MP_MEMBERS_ATTR:
                self.mp_members.append(v.strip().upper())

            else:
                pass # ignore unrecognized lines

        if not self.route_set:
            raise Exception("Can not create RouteSetObject out of text: "+str(textlines))


    def getKey(self):
        return self.route_set

    def __str__(self):
        return 'RouteSetbject: %s -< %s + %s'%(self.route_set, str(self.members), str(self.mp_members))


    def match(self, prefix):
        # TODO
        return True


class HashObjectDir(object):
    """
    Common direcotry for objects that have one unique key and unlike route or route6
    objects do not need special lookup machinery because of their semantics.
    Once the object is constructed (out of a RIPE DB snapshot file) it contains
    table attribute, which is a hastable with keys that uses getKey() of the objects
    to index them.
    """
    def __init__(self, filename, objType):
        self.table={}
        for o in RpslObject.parseRipeFile(filename, objType):
            self.table[o.getKey()]=o



######################################################################


# File handling

def ripe_route_pickle(day):
    return common.resultdir(day)+RIPE_DB_ROUTE_PICKLE

def ripe_route6_pickle(day):
    return common.resultdir(day)+RIPE_DB_ROUTE6_PICKLE

def ripe_autnum_pickle(day):
    return common.resultdir(day)+RIPE_DB_AUTNUM_PICKLE

def ripe_asset_pickle(day):
    return common.resultdir(day)+RIPE_DB_ASSET_PICKLE

def ripe_filterset_pickle(day):
    return common.resultdir(day)+RIPE_DB_FILTERSET_PICKLE

def ripe_routeset_pickle(day):
    return common.resultdir(day)+RIPE_DB_ROUTESET_PICKLE


def decode_ripe_tgz_filename(filename):
    """
    Input filename='ripedb-2014-2-16-1-17-2.txt.bz2'
    Output (ipv6,year,month,day,hour,min,sec)
    """

    basename=os.path.basename(filename)
    g=basename.split('-')
    if g[0] != 'ripedb':
        raise Exception('Can not parse filename: '+filename)

    g[6]=g[6].split('.',1)[0]

    return (int(g[1]),int(g[2]),int(g[3]),int(g[4]),int(g[5]),int(g[6]))



# Route checking code

def check_ripe_route(path_vector, iana_dir, ripe_routes):
    """
    Do the actual checking of a route. Returns vector
    (prefix, as-path, routeObj or None, status) and
    status might be 0=OK, 1=aggregate, 2=missing origin, 3=not match,
    4=not found, 5=non-RIPE NCC.
    """

    # assert...
    if not path_vector[1].find('/')>0:
        raise Exception("Pfx not normalized: "+str(path_vector))

    # check the prefix is not an aggregate
    if len(path_vector[3].split(' '))>=2:
        orig=path_vector[3].split(' ')[-2]
        if orig.find("{")>=0:
            #common.d("Skipping prefix with aggregated begining of ASpath:", orig)
            return (path_vector[1],path_vector[3],None,1)

    else:
        # localy originated prefix?
        common.w('Skipping prefix with less than 2 records in ASpath: ', path_vector)
        return (path_vector[1],path_vector[3],None,2)

    iananet=iana_dir.resolve_network(path_vector[1])
    if iananet[2] == 'RIPE NCC':
        routes=ripe_routes.getRouteObjs(path_vector[1])
        if routes:
            notmatchro=[]
            for r in routes:
                if r.origin == 'AS'+orig:
                    #common.d("Route object match for", path_vector[1], '('+path_vector[3]+"):", str(r))
                    return (path_vector[1], path_vector[3], r, 0)
                else:        
                    #common.d("Route object NOT match", str(r.route), "("+str(r.origin)+") found for", str(pv[1]), "from AS"+str(orig))
                    notmatchro.append(r)
            else: # for finished without matching
                return (path_vector[1], path_vector[3], notmatchro, 3)
        else:
            #common.d("No route object found for", str(path_vector[1]))
            return(path_vector[1], path_vector[3], None, 4)
    else:
        #common.d("Skipping non-RIPE NCC network", path_vector[1], "which is part of", str(iananet[0]), "("+str(iananet[2])+")")
        return (path_vector[1], path_vector[3], None, 5)



def check_ripe_routes(day, ianadir, host, ipv6=False, bestonly=True):
    """
    Check routes from BGP dump against RIPE route objects. Ignore all routes
    from the BGP dump that are either from outside of the RIPE region or
    does not contain enough information to check their origin. The most
    common reason for that is that routes are originated locally or that
    there has been aggregation that (naturally) stands on the beginning of
    the AS path.

    Returns list of (prefix, as-path, routeObj or None, status) and
    status might be 0=OK, 1=aggregate, 2=missing origin, 3=not match,
    4=not found, 5=non-RIPE NCC
    
    """
    common.d("Checking RIPE routes against route objects for day", day)

    res=[]
    
    riperoutes=None
    if ipv6:
        riperoutes=common.load_pickle(ripe_route6_pickle(day))
    else:
        riperoutes=common.load_pickle(ripe_route_pickle(day))

    bgpdump=common.load_pickle(bgp.bgpdump_pickle(day, host, ipv6))
    for path_vector in bgpdump:
        if bestonly and not (path_vector[0] and '>' in path_vector[0]):
            continue

        yield check_ripe_route(path_vector, ianadir, riperoutes)



RIPE_ROUTES_MATCH_LEGEND=['OK', 'no-search aggregate', 'origin missing', 'AS not match',
                          'route obj not found', 'non-ripe']

def report_ripe_routes_day(route_list, day, outdir, ipv6=False):
    """
    Generate text report for a day and return stats for further graphing.

    Returns list of tuples for graphing (day, total_ok, total_aggregate,
    total_missing, total_notmatch, total_notfound, total_nonripe, total)
    """

    total_ok=0
    total_aggregate=0
    total_missing=0
    total_notmatch=0
    total_notfound=0
    total_nonripe=0
    total=0

    outpick=[]
    for r in route_list:
        # r = (prefix, as-path, routeObj or None, status)
        # status: 0=OK, 1=aggregate, 2=missing origin, 3=not match,
        # 4=not found, 5=non-RIPE NCC
        
        total+=1

        if r[3]==0:
            total_ok+=1
        elif r[3]==1:
            total_aggregate+=1
        elif r[3]==2:
            total_missing+=1
        elif r[3]==3:
            total_notmatch+=1
        elif r[3]==4:
            total_notfound+=1
        elif r[3]==5:
            total_nonripe+=1
        else:
            raise Exception("Unknown status in "+str(r))

    filename=outdir+(RIPE_BGP2ROUTES6_TXT if ipv6 else RIPE_BGP2ROUTES4_TXT)
    common.d("Generating file", filename)
    with open(filename, 'w') as of:
        of.write("%s: %d\n"%('total', total))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[0], total_ok))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[1], total_aggregate))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[2], total_missing))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[3], total_notmatch))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[4], total_notfound))
        of.write("%s: %d\n"%(RIPE_ROUTES_MATCH_LEGEND[5], total_nonripe))

    return (day, total_ok, total_aggregate, total_missing,
            total_notmatch, total_notfound, total_nonripe)





def ripe_filter_violating_routes(matched_pfxes):
    """ Filter routes from result of check_ripe_routes() that needs attention.
    Return list of prefixes. """

    for p in matched_pfxes:
        if p[3]==3 or p[3]==4: # not match or not found
            yield p[0]


def ripe_gen_route_timeline(violators, ripe_days, bgp_days, ipv6=False):
    """ Generate timeline for each suspect route. """

    timeline={}

    for v in violators:
        timeline[v]=[]
    
    for d in sorted(ripe_days):
        if d in bgp_days: # test if we have BGP data for the day
            common.d("ripe_gen_route_timeline: Working on day %s"%str(d))
            bgp2routesfn=common.resultdir(d)+(RIPE_BGP2ROUTES6_PICKLE if ipv6 else RIPE_BGP2ROUTES4_PICKLE)
            dayres=common.load_pickle(bgp2routesfn)
            # dayres contains list of tuples (prefix, as-path, routeObj or None, status)

            for rv in dayres:
                if rv[0] in timeline:
                    if len(timeline[rv[0]])==0 or timeline[rv[0]][-1] != rv[1:]:
                        timeline[rv[0]].append(tuple([d]+list(rv)))

    return timeline

def report_route_timeline(timeline, ipv6=False):
    """ Generate textual report on prefixes that has or had problems. """

    txtout=common.resultdir()+(RIPE_ROUTE6_VIOLATION_TIMELINE if ipv6 else RIPE_ROUTE_VIOLATION_TIMELINE)
    common.d('Writing timeline to:', txtout)
    with open(txtout, 'w') as tf:
        for pfx in timeline.keys():
            for r in timeline[pfx]:
                # r = (day, prefix, as-path, routeObj or None, status)
                # use RIPE_ROUTES_MATCH_LEGEND for status

                if r[4] == 3: # not match
                    tf.write('%s %s (%s) %s: ripe-db orig: %s\n'%(str(r[0]),
                        str(r[1]), str(r[2]), RIPE_ROUTES_MATCH_LEGEND[r[4]], str([ro.origin for ro in r[3]])))
                elif r[4] == 4: # not found
                    tf.write('%s %s (%s) %s\n'%(str(r[0]), str(r[1]), str(r[2]), RIPE_ROUTES_MATCH_LEGEND[r[4]]))
                else:
                    raise Exception("Unexpected status: "+str(r[4]))

            tf.write('\n--------------------------------------------------\n\n')


# Path checking code

def normalize_aspath(text):
    text = text.replace('{', '').replace('}', '')
    asns = text.split()[:-1]
    return ['AS'+asn for asn in asns]


def check_ripe_path_step(pfx, asn, current_aspath, previous_as, next_as,
                         autnum_dir, asset_dir, routeset_dir, fltrset_dir, ipv6=False):
    """ TODO desc """

    common.d('Checking path for', pfx, 'step from', previous_as, 'to', next_as, 'via', asn)

    if asn in autnum_dir.table:
        autnum=autnum_dir.table[asn]
        import_match=False
        export_match=False
        
        for ir in autnum.import_list:
            if ir.match(previous_as, pfx, current_aspath, asset_dir, fltrset_dir, routeset_dir, ipv6):
                import_match=True
                break

        for ir in autnum.mp_import_list:
            if ir.match(previous_as, pfx, current_aspath, asset_dir, fltrset_dir, routeset_dir, ipv6):
                import_match=True
                break

        if not import_match:
            common.d('Invalid: Import match missing.')
            return 3 # import match missing

        for er in autnum.export_list:
            if er.match(next_as, pfx, current_aspath, asset_dir, fltrset_dir, routeset_dir, ipv6):
                export_match=True
                break

        for er in autnum.mp_export_list:
            if er.match(next_as, pfx, current_aspath, asset_dir, fltrset_dir, routeset_dir, ipv6):
                export_match=True
                break

        if not export_match:
            common.d('Invalid: Export match missing.')
            return 4 # export match missing
    else:
        common.d('Dunno: ASN not in RIPE region.')
        return 2 # ASN not in RIPE region (=not found in aut-num directory)

    common.d("Valid. Match.")
    return 0 # otherwise it must have matched both import and export
    


def check_ripe_path(path_vector, autnum_dir, asset_dir, routeset_dir, filterset_dir, ipv6=False, myas=None):
    """
    TODO descr
    """
    
    # assert...
    if not path_vector[1].find('/')>0:
        raise Exception("Pfx not normalized: "+str(path_vector))

    aspath = normalize_aspath(path_vector[3])
    status  = []
    allinripe = True

    
    
    # go through as-path one by one AS and check routes
    for i,asn in enumerate(aspath):
        previous_as = (aspath[i-1] if i>0 else myas)
        if previous_as == None:
            continue

        next_as = (aspath[i+1] if i<(len(aspath)-1) else None)
        
        res = check_ripe_path_step(path_vector[1], asn, aspath[i:], previous_as, next_as,
                                   autnum_dir, asset_dir, routeset_dir, filterset_dir, ipv6)

        if res == 2: # means that the ASN is out of RIPE region
            allinripe = False

        status.append((asn, res))

    return (path_vector, allinripe, status)


def check_ripe_paths(day, ianadir, host, ipv6=False, bestonly=True, myas=None):
    """
    Check paths during their travel in the RIPE region.
    Returns (path_vector, whole_path_in_ripe, status, status_per_as) where
    path_vector is BGP path vector from checked host table for the day,
    whole_path_in_ripe indicates whether whole path is withing
    RIPE region (= no AS in as-path lays outside of RIPE),
    ...
    status_per_as = list of check result statuses for each AS in as-path

    status list:
    0 = match (=OK)
    1 = route uncheckable (local or aggregate... =uncheckable)
    2 = ASN outside of RIPE NCC region (=uncheckable)
    3 = prevASN not found
    4 = nextASN not found (might be suppressed by the status=3 which has precedecnce
    but the AS shoudl not export prefix that it didnt imported in documented way...)
    5 = ??? TODO
    """
    # TODO. Plan:
    # load BGP dump, aut-num, as-set and filter-set pickles
    # pick routes that belongs to RIPE and verify route object by
    # calling check_ripe_route(path_vector, iana_dir, ripe_routes)
    # If the result is 0 (=OK) then start checking the as-path:
    # for each AS from the right (= from beginning) find it's
    # aut-num object and check that it is being originated locally for
    # the first one or imported from right and expoted to the left.
    # The only exception is the last AS that does not need to export.
    # Drawback: It does not check the last AS in the path.
    # So add the own-AS external fed variable???

    common.d("Checking RIPE paths against aut-num & sets objects for day", day)

    res=[]

    # Load data for a day
    riperoutes_pkl=(ripe_route6_pickle(day) if ipv6 else ripe_route_pickle(day))
    riperoutes=common.load_pickle(riperoutes_pkl)

#    route_dir_pkl = ripe_route6_pickle(d) if ipv6 else ripe_route_pickle(d)
#    route_dir = common.load_pickle(route_dir_pkl)

    asset_dir = common.load_pickle(ripe_asset_pickle(day))
    autnum_dir = common.load_pickle(ripe_autnum_pickle(day))
    filterset_dir = common.load_pickle(ripe_filterset_pickle(day))
    routeset_dir = common.load_pickle(ripe_routeset_pickle(day))

    bgpdump=common.load_pickle(bgp.bgpdump_pickle(day, host, ipv6))

    # Run the check for BGP data of the day
    for path_vector in bgpdump:
        if bestonly and not (path_vector[0] and '>' in path_vector[0]):
            continue

        rc = check_ripe_route(path_vector, ianadir, riperoutes)
        if rc[3] == 0 or rc[3] == 5: # if the route checks in RIPE DB or it is outside of RIPE region
            yield check_ripe_path(path_vector, autnum_dir, asset_dir, routeset_dir, filterset_dir, ipv6, myas)
        else:
            common.d("Origin does not match... No point in checking the path.", path_vector)
            status  = [(asn, 0) for asn in normalize_aspath(path_vector[3])]
            if status:
                status[-1] = (status[-1][-1], 1) # 1=route object failure or uncheckable route,
            # either local route or aggregate route generated in some remote location
            yield (path_vector, True, status)




def report_ripe_paths_day(check_res, day, outdir, ipv6=False):
    # TODO
    return ()



def module_prepare_day(fn, d):
    """
    Prepare datastructures for RPS module for a day.
    fn is a filename of the daily RIPE archive and d is a Day object
    that represent the day.
    """
    
    # skip parsed days (enumerate all needed results in condition)
    if (os.path.isfile(ripe_route_pickle(d)) and
        os.path.isfile(ripe_route6_pickle(d)) and
        os.path.isfile(ripe_autnum_pickle(d)) and
        os.path.isfile(ripe_asset_pickle(d)) and
        os.path.isfile(ripe_filterset_pickle(d)) and
        os.path.isfile(ripe_routeset_pickle(d))):
        common.d("Skipping dir", d, "because we have all needed results.")
        return

    common.d("Unpacking file", fn, "for time", d, ".")
    tmpdir=common.unpack_ripe_file(fn)
    common.d("Resulting dir:", tmpdir)
    try:
        # ripe.db.route
        common.d("Parsing", tmpdir+RIPE_DB_ROUTE)
        if os.path.isfile(tmpdir+RIPE_DB_ROUTE):
            ros=RouteObjectDir(tmpdir+RIPE_DB_ROUTE, False)
            common.save_pickle(ros, ripe_route_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_ROUTE)

        # ripe.db.route6
        common.d("Parsing", tmpdir+RIPE_DB_ROUTE6)
        if os.path.isfile(tmpdir+RIPE_DB_ROUTE6):
            ros6=RouteObjectDir(tmpdir+RIPE_DB_ROUTE6, True)
            common.save_pickle(ros6, ripe_route6_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE6_DB_ROUTE)
                    
        # ripe.db.aut-num
        common.d("Parsing", tmpdir+RIPE_DB_AUTNUM)
        if os.path.isfile(tmpdir+RIPE_DB_AUTNUM):
            ao=HashObjectDir(tmpdir+RIPE_DB_AUTNUM, AutNumObject)
            common.save_pickle(ao, ripe_autnum_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_AUTNUM)

        # ripe.db.as-set
        common.d("Parsing", tmpdir+RIPE_DB_ASSET)
        if os.path.isfile(tmpdir+RIPE_DB_ASSET):
            ass=HashObjectDir(tmpdir+RIPE_DB_ASSET, AsSetObject)
            common.save_pickle(ass, ripe_asset_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_ASSET)

        # ripe.db.filter-set
        common.d("Parsing", tmpdir+RIPE_DB_FILTERSET)
        if os.path.isfile(tmpdir+RIPE_DB_FILTERSET):
            fs=HashObjectDir(tmpdir+RIPE_DB_FILTERSET, FilterSetObject)
            common.save_pickle(fs, ripe_filterset_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_FILTERSET)

        # ripe.db.route-set
        common.d("Parsing", tmpdir+RIPE_DB_ROUTESET)
        if os.path.isfile(tmpdir+RIPE_DB_ROUTESET):
            fs=HashObjectDir(tmpdir+RIPE_DB_ROUTESET, RouteSetObject)
            common.save_pickle(fs, ripe_routeset_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_ROUTESET)

    finally:
        common.d("Removing dir", tmpdir, "expanded from", fn, "for time", d, ".")
        common.cleanup_path(tmpdir)


def module_prepare_thread(tasks):
    for t in tasks:
        module_prepare_day(t[0], t[1])



# Module interface

def module_prepare(data_root_dir):
        """ Prepare datastructures for RPSL module. """
        out_days = []
        tasks = [[] for i in range(0,MAX_THREADS)]

        for i,fn in enumerate(common.enumerate_files(data_root_dir+'/ripe','ripedb-[0-9-]+\.tar\.bz2')):
            d = common.Day(decode_ripe_tgz_filename(fn)[0:3])
            out_days.append(d)

            tasks[i%MAX_THREADS].append((fn,d))

        if MAX_THREADS > 1:
            threads=[]
            for i in range(0,MAX_THREADS):
                t=threading.Thread(target=module_prepare_thread, args=[tasks[i]])
                t.start()
                threads.append(t)

            for t in threads:
                t.join()
        else: # no threading
            module_prepare_thread(tasks[0])

        return out_days



def module_run(ripe_days, ianadir, host, bgp_days, ipv6):
    common.d("rpsl.module_run ripe_days:", ripe_days)
    common.d("rpsl.module_run bgp_days:", bgp_days)

    route_totals=[]
    route_violators={}
    path_totals=[]
    for d in ripe_days:
        if d in bgp_days: # test if we have BGP data for the day
            # check routes
            res=None
            bgp2routesfn=common.resultdir(d)+(RIPE_BGP2ROUTES6_PICKLE if ipv6 else RIPE_BGP2ROUTES4_PICKLE)
            if not os.path.isfile(bgp2routesfn):
                common.d("Creating file", bgp2routesfn)
                res=list(check_ripe_routes(d, ianadir, host, ipv6, True))
                common.save_pickle(res, bgp2routesfn)
            else:
                res=common.load_pickle(bgp2routesfn)

            for v in ripe_filter_violating_routes(res):
                if not v in route_violators:
                    route_violators[v]=True

            route_totals.append(report_ripe_routes_day(res, d, common.resultdir(d), ipv6))

            # check paths
            bgp2pathsfn=common.resultdir(d)+(RIPE_BGP2PATHS6_PICKLE if ipv6 else RIPE_BGP2PATHS4_PICKLE)
            if not os.path.isfile(bgp2pathsfn):
                common.d("Creating file", bgp2pathsfn)
                res=list(check_ripe_paths(d, ianadir, host, ipv6, True, MY_ASN))
                common.save_pickle(res, bgp2pathsfn)
            else:
                res=common.load_pickle(bgp2pathsfn)

            path_totals.append(report_ripe_paths_day(res, d, common.resultdir(d), ipv6))

        else:
             common.w('Missing BGP data for day %s'%str(d))

    # Graph totals
    if route_totals:
        common.d("Generating graph with pfx", common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'))
        graph.gen_multilineplot(route_totals, common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'), legend=RIPE_ROUTES_MATCH_LEGEND)

    # Revisit common.resultdir(d)+RIPE_BGP2ROUTES_PICKLE for each day and cross check time to fix
    if route_violators:
        common.d("Crating route timeline...")
        tl=ripe_gen_route_timeline(route_violators.keys(), ripe_days, bgp_days, ipv6)
        report_route_timeline(tl, ipv6)

    # TODO: Path totals





# Unit test interface

def main():
#    raise Exception("This test does not work unless special environment is set.")

    def test_routes():
        ripeRoutes=RouteObjectDir("/home/brill/ext/tmp/ripe.db.route", False)
        # ripeRoutes.tree.dump()
        print str(ripeRoutes.getRouteObjs("2.10.0.0/16"))

        ripeRoutes=RouteObjectDir("/home/brill/ext/tmp/ripe.db.route6", True)
        # ripeRoutes.tree.dump()
        print str(ripeRoutes.getRouteObjs("2a00:1028::/32"))


    def test_autnums():
        ripeAutNums=RpslObject.parseRipeFile('/home/brill/ext/tmp/ripe.db.aut-num', AutNumObject)
        for autnum in ripeAutNums:
            print str(autnum)

    def test_assets():
        ripeAsSets=RpslObject.parseRipeFile('/home/brill/ext/tmp/ripe.db.as-set', AsSetObject)
        for asset in ripeAsSets:
            print str(asset)

    def test_fltrsets():
        filterSets=RpslObject.parseRipeFile('/home/brill/ext/tmp/ripe.db.filter-set', FilterSetObject)
        for fset in filterSets:
            print str(fset)

    def test_routesets():
        routeSets=RpslObject.parseRipeFile('/home/brill/ext/tmp/ripe.db.route-set', RouteSetObject)
        for rset in routeSets:
            print str(rset)

    test_routes()
    test_autnums()
    test_assets()
    test_fltrsets()
    test_routesets()




if __name__ == '__main__':
    main()
