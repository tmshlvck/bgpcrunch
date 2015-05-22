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
import ipaddr
import traceback
import threading
import gc

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
RIPE_DB_PEERINGSET='/ripe.db.peering-set'

RIPE_DB_ROUTE_PICKLE='/ripe.route.pickle'
RIPE_DB_ROUTE6_PICKLE='/ripe.route6.pickle'
RIPE_DB_AUTNUM_PICKLE='/ripe.autnum.pickle'
RIPE_DB_ASSET_PICKLE='/ripe.asset.pickle'
RIPE_DB_FILTERSET_PICKLE='/ripe.filterset.pickle'
RIPE_DB_ROUTESET_PICKLE='/ripe.routeset.pickle'
RIPE_DB_PEERINGSET_PICKLE='/ripe.peeringset.pickle'

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
    MEMBEROF_ATTR = 'MEMBER-OF'
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.route=None
        self.origin=None
        self.members=None

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.ROUTE_ATTR:
                self.route=v.strip()

            elif a==self.ORIGIN_ATTR:
                if v[:2] == 'AS':
                    self.origin=v.strip().upper()
                else:
                    raise Exception("Can not parse tuple "+a+":"+v)

            elif a==self.MEMBER_OF:
                self.members+=[m.strip() for m in v.strip().split(',')]

            else:
                pass # ignore unknown lines

            # ??? Add holes. But why? It is impossible to check hole existence at
            # this point. New module and new walk through is needed perhaps.

            
        if not (self.route and self.origin):
            raise Exception("Can not create RouteObject out of text: "+str(textlines))

    def getKey(self):
        return self.route

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

    def enumerateObjs(self):
        for k in self.originTable.keys():
            for o in self.originTable[k]:
                yield o





# Aut-num object machinery

EXPRESSION_DECODE=re.compile('^([^\{\}]{5,}.*|\{(.+)\}(\s+REFINE .*|\s+EXCEPT .*)?)$')
FACTOR_SPLIT_ACCEPT='ACCEPT'
FACTOR_SPLIT_ANNOUNCE='ANNOUNCE'
FACTOR_SPLIT_NETWORKS='NETWORKS'
FACTOR_SPLIT_FROM='FROM '
FACTOR_SPLIT_TO='TO '
AFI_MATCH=re.compile('^AFI\s+([^\s]+)\s+(.*)$')

IMPORT_FACTOR_MATCH=re.compile('^FROM\s+([^\s]+)(\s+(.*)?\s?ACCEPT(.+))?$')
EXPORT_FACTOR_MATCH=re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?ANNOUNCE(.+))?$')
DEFAULT_FACTOR_MATCH=re.compile('^TO\s+([^\s]+)(\s+(.*)?\s?NETWORKS(.+)|.*)?$')

ASN_MATCH=re.compile('^AS[0-9]+$')
PFX_FLTR_MATCH=re.compile('^\{([^}]+)\}(\^[0-9\+-])?$')
PFX_FLTR_PARSE=re.compile('^([0-9A-F:\.]+/[0-9]+)(\^[0-9\+-]+)?$')

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
    def _decomposeExpression(text, defaultRule=False):
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
                fltr=(FACTOR_SPLIT_ACCEPT+' '+fltr).strip()
            elif e.find(FACTOR_SPLIT_ANNOUNCE)>-1:
                [sel,fltr] = e.split(FACTOR_SPLIT_ANNOUNCE, 1)
                fltr=(FACTOR_SPLIT_ANNOUNCE+' '+fltr).strip()
            elif e.find(FACTOR_SPLIT_NETWORKS)>-1:
                [sel,fltr] = e.split(FACTOR_SPLIT_NETWORKS, 1)
                fltr=(FACTOR_SPLIT_NETWORKS+' '+fltr).strip()
            else:
                if defaultRule: # default: rule does not need to include filter, then default to ANY
                    fltr='ANY'
                else:
                    common.w("Syntax error: Can not find selectors in:", e, "decomposing expression:", text)
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

        defaultRule = (self.__class__.__name__ == 'AutNumDefaultRule')
        factors=AutNumRule._decomposeExpression(self.text, defaultRule)

        return (afi,[AutNumRule._normalizeFactor(f, factors[1]) for f in factors[0]])


    @staticmethod
    def isASN(asn):
            return ASN_MATCH.match(str(asn).strip()) != None


    @staticmethod
    def isPfxFilter(fltr):
        m=PFX_FLTR_MATCH.match(fltr.strip())
        if m:
            return m.group(1)
        else:
            return None

    @staticmethod
    def matchPfxFltr(fltr, prefix, ipv6):
        def _parseRange(rng, lowbound, ipv6):
            PARSE_RANGE=re.compile('^\^([0-9]+)-([0-9]+)$')
            maxpl = 128 if ipv6 else 32
            rng=rng.strip()
                
            if rng == '^+':
                return [str(lowbound), maxpl]
            elif rng == '^-':
                return [str(lowbound+1), maxpl]

            elif rng[1:].isdigit():
                return [int(rng),int(rng)]
                
            elif PARSE_RANGE.match(rng):
                m=PARSE_RANGE.match(rng)
                return [m.group(1), m.group(2)]

            else:
                common.w("Can not parse range:", rng)
                return [0,maxpl]

        m=PFX_FLTR_MATCH.match(fltr.strip())
        rng=[0,128] if ipv6 else [0,32]
        rngset=False
        if m.group(2):
            rng = _parseRange(m.group(2), ipv6)

        for f in m.group(1).strip().split(','):
            f=f.strip()
            m=PFX_FLTR_PARSE.match(f)
            fnet=None
            if m:
                fnet=ipaddr.IPNetwork(m.group(1))
                if m.group(2):
                    if not rngset:
                        rng = _parseRange(m.group(2), fnet.prefixlen, ipv6)
                    else:
                        common.w("Range mismatch in prefix filter:", fltr)
            else:
                raise Exception("Can not parse filter: "+fltr+" matching with pfx "+prefix)

            pnet=ipaddr.IPNetwork(prefix)

            if not rngset:
                rng=[fnet.prefixlen, fnet.prefixlen]

            if (pnet in fnet) and (rng[0] <= pnet.prefixlen) and (rng[1] >= pnet.prefixlen):
                return True

        # no match means filter failed -> false
        return False

            
    @staticmethod
    def matchFilter(fltr, prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6=False):
        """ Matches filter fltr to prefix with currentAsPath.
        Using assetDirectory, fltrsetDirectory and rtsetDirectory.

        Returns:
        0 when filter matches (=OK)
        1-3 are reserved for calling functions
        4 when fltr ASN != origin
        5 when as-set recursive match fails
        6 when unknown as-set is in the filter
        7 PeerAS match failed
        8 { prefix^range } match failed
        9 composed expression failed
        10 unknown fltr-set
        11 unkown route-set
        12 unknown filter
        """
        
#        common.d("Matching filter", fltr, 'prefix', prefix, 'current_aspath', str(currentAsPath))

        origin=currentAsPath[-1].strip()
        fltr=fltr.strip()


        # Recrusion for composed filters (with NOT, AND and OR)
        def findOper(text, oper):
            """ Find the first occurance of operator that is out of the parentheses. """
            pc=0
            for i,c in enumerate(text):
                if c == '(':
                    pc+=1
                if c == ')':
                    pc-=1
                if pc == 0 and text[i:].startswith(oper):
                    return i
            return -1

        op=" OR "
        i=findOper(fltr, op)
        if i>=0:
            a=AutNumRule.matchFilter(fltr[:i], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            b=AutNumRule.matchFilter(fltr[i+len(op):], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            return (0 if a == 0 or b == 0 else 9)

        op=" AND "
        i=findOper(fltr, op)
        if i>=0:
            a=AutNumRule.matchFilter(fltr[:i], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            b=AutNumRule.matchFilter(fltr[i+len(op):], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            return (0 if a == 0 and b == 0 else 9)

        op="NOT "
        i=findOper(fltr, op)
        if i>=0:
            a=AutNumRule.matchFilter(fltr[i+len(op):], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            return (0 if not a == 0 else 9)

        # Parentheses

        if fltr[0] == '(':
            if fltr[-1] == ')':
                return AutNumRule.matchFilter(fltr[1:-1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            else:
                raise Exception("Can not parse parentheses in filter:", fltr)

        # Atomic statements
        
        if fltr.strip() == 'ANY':
            return 0

        elif fltr.strip() == 'PEERAS':
            if origin == currentAsPath[0]: # allow as-path prepending, i.e. aspath can be [x,x,x,x] and origin x
                return 0
            else:
                return 7
        
        elif AutNumRule.isASN(fltr):
            if fltr == origin:
                #common.d("True, fltr ASN == origin", origin)
                return 0
            else:
                #common.d("False, fltr ASN != origin f:", fltr, 'o:', origin)
                return 4

        elif AsSetObject.isAsSet(fltr):
            if fltr in assetDirectory.table:
                if assetDirectory.table[fltr].recursiveMatch(origin, assetDirectory):
                    #common.d('True, as-set recursive match f:', fltr, 'o:', origin)
                    return 0
                else:
                    #common.d('False, no as-set recursive match f:', fltr, 'o:', origin)
                    return 5
            else:
                #common.d('False, as-set not known. f:', fltr, 'o:', origin)
                return 6

        elif AutNumRule.isPfxFilter(fltr):
            if AutNumRule.matchPfxFltr(fltr, prefix, ipv6):
                return 0
            else:
                return 8

        elif FilterSetObject.isFltrSet(fltr):
            if fltr in fltrsetDirectory:
                r=AutNumRule.matchFilter(fltrsetDirectory[fltr].filter, prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
                if r == 0:
                    return 0
                return AutNumRule.matchFilter(fltrsetDirectory[fltr].mp_filter, prefix, currentAsPath, assetDirectory, fltrsetDirectory, rtsetDirectory, ipv6)
            else:
                return 10

        elif RouteSetObject.isRouteSet(fltr):
            # TODO
            return 11

        # TODO <regular expression>

        # Dunno, return False
        common.w("Can not parse filter:", fltr)
        return 12


    def match(self, subject, prefix, currentAsPath, assetDirectory, fltrsetDirectory,
              rtsetDirectory, prngsetDirectory, ipv6=False):
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

        returns:
        0 when match is OK
        1 when AFI does not match
        2 when subject can not be expanded (= not ASN nor AS-SET)
        3 when not match for the subject has been found in factors
        >=4 and filter match failed (see AutNumRule.matchFilter for details)
        """

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
                return 1

        # Walk through factors and find whether there is subject match,
        # run the filter if so
        for f in res[1]:
            #common.d("Match? sub=", subject, 'f=', str(f))

            if self.isASN(f[0]):
                if f[0] == subject:
                    return self.matchFilter(f[1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6)

            elif AsSetObject.isAsSet(f[0]):
                if f[0] in assetDirectory.table:
                    if assetDirectory.table[f[0]].recursiveMatch(subject, assetDirectory):
                        return self.matchFilter(f[1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6)

            elif PeeringSetObject.isPeeringSet(f[0]):
                if f[0] in prngsetDirectory.table:
                    if prngsetDirectory.table[f[0]].recursiveMatch(subject, prngsetDirectory):
                        return self.matchFilter(f[1], prefix, currentAsPath, assetDirectory, fltrsetDirectory, ipv6)

            else:
                #raise Exception("Can not expand subject: "+str(f[0]))
                common.w("Can not expand subject:", str(f[0]))
                return 2

        # No match of factor for the subject means that the prefix should not appear
        return 3

    

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
    MEMBEROF_ATTR="MEMBER-OF"
    
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.aut_num=None
        self.import_list=[]
        self.export_list=[]
        self.mp_import_list=[]
        self.mp_export_list=[]
        self.memberof_list=[]

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

            elif a==self.MEMBEROF_ATTR:
                self.memberof_list = self.memberof_list + list([m.strip() for m in v.split(',')])
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

    def recursiveMatch(self, target, hashObjDir, recursionList=None):
        if recursionList == None:
            recursionList = []
        
#        common.d("AsSetObject recursiveMatch: target", target, 'in', self.getKey(), 'recursionList', recursionList)
#        common.d("Members:", self.members)
        # prevent recusion loop
        if self.getKey() in recursionList:
            return False
        recursionList.append(self.getKey())
        
        if target in self.members:
            return True

        for m in self.members:
            if self.isAsSet(m) and m in hashObjDir.table:
                r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
                if r:
                    return True

        return False

    def __str__(self):
        return 'AsSetObject: %s -< %s'%(self.as_set, str(self.members))


class PeeringSetObject(RpslObject):
    """ Internal representation of prng-set RPSL object. """

    PEERINGSET_ATTR='PEERING-SET'
    PEERING_ATTR='PEERING'
    MP_PEERING_ATTR='MP-PEERING'

    @staticmethod
    def _parsePeering(p):
        return p.strip().split(' ')[0]

    @staticmethod
    def isPeeringSet(name):
        """ Returs True when the name appears to be as-set name (=key)
        according to RPSL specs. """
        return str(name).upper().find('PRNG-') > -1
    
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.peering_set=None
        self.peering=[]
        self.mp_peering=[]

        for (a,v) in RpslObject.splitLines(self.text):
            if a==self.PEERINGSET_ATTR:
                self.peering_set=v.strip().upper()
                
            elif a==self.PEERING_ATTR:
                self.peering.append(PeeringSetObject._parsePeering(v))

            elif a==self.MP_PEERING_ATTR:
                self.mp_peering.append(PeeringSetObject._parsePeering(v))
            else:
                pass # ignore unrecognized lines

        if not self.peering_set:
            raise Exception("Can not create AsSetObject out of text: "+str(textlines))


    def getKey(self):
        return self.peering_set

    def recursiveMatch(self, target, hashObjDir, recursionList=None):
        if recursionList == None:
            recursionList = []
        
#        common.d("PeeringSetObject recursiveMatch: target", target, 'in', self.getKey(),
#                 'recursionList', recursionList)

        # prevent recusion loop
        if self.getKey() in recursionList:
            return False
        recursionList.append(self.getKey())
        
        if target in self.peering or target in self.mp_peering:
            return True

        for m in (self.peering + self.mp_peering):
            if self.isPeeringSet(m) and m in hashObjDir.table:
                r = hashObjDir.table[m].recursiveMatch(target, hashObjDir, recursionList)
                if r:
                    return True

        return False

    def __str__(self):
        return 'PeeringSetObject: %s -< %s mp: %s'%(self.peering_set, str(self.peering), str(self.mp_peering))



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

    @staticmethod
    def isFltrSet(fltrsetid):
        """ Returs True when the name appears to be filter-set name (=key)
        according to RPSL specs. """
        return str(fltrsetid).upper().find('FLTR-') > -1

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
                self.members+=[r.strip() for r in v.strip().split(',')]

            elif a==self.MP_MEMBERS_ATTR:
                self.mp_members+=[r.strip() for r in v.strip().split(',')]

            else:
                pass # ignore unrecognized lines

        if not self.route_set:
            raise Exception("Can not create RouteSetObject out of text: "+str(textlines))

    @staticmethod
    def isRouteSet(rsid):
        """ Returs True when the name appears to be route-set name (=key)
        according to RPSL specs. """
        return str(fltrsetid).upper().find('RS-') > -1

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

def ripe_peeringset_pickle(day):
    return common.resultdir(day)+RIPE_DB_PEERINGSET_PICKLE

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
    asns = text.split()[:-1] # remove i or e or ? in the end of the string (= which means on
    # the beginning of the AS path)
    return ['AS'+asn for asn in asns]


def check_ripe_path_step(pfx, asn, current_aspath, previous_as, next_as,
                         autnum_dir, asset_dir, routeset_dir, fltrset_dir, prngset_dir, ipv6=False):
    """
    Check one step in as-path from BGP by means of resolving proper aut-num
    object for the asn and check filters based on prefix that is being checked
    and current_aspath.

    TODO descr

    Returns:
    0 = step match (=OK)
    1 = subject expansion failed (=recursion trhough as-set failed)
    2 = ASN not in RIPE region (=not found in aut-num directory)
    300-399 = import match filter failure
    300 = can not find matching rule, otherwise subtract 300 and see matchFilter()
    400-499 = export match filter failure
    400 = can not find matchin rule, otherwise subtract 400 and see matchFilter()
    
    """

#    common.d('Checking path for', pfx, 'step from', previous_as, 'to', next_as, 'via', asn)

    if asn in autnum_dir.table:
        autnum=autnum_dir.table[asn]
        import_match=False
        export_match=False
        status=0

        if previous_as == None: # AS is the originator
            import_match = True
        else:
            for ir in autnum.import_list:
                m=ir.match(previous_as, pfx, current_aspath, asset_dir, fltrset_dir,
                           routeset_dir, prngset_dir, ipv6)
                if m == 0:
                    import_match=True
                    break
                else:
                    if m>3:
                        status=m

            for ir in autnum.mp_import_list:
                m=ir.match(previous_as, pfx, current_aspath, asset_dir, fltrset_dir,
                           routeset_dir, prngset_dir, ipv6)
                if m == 0:
                    import_match=True
                    break
                else:
                    if m>3:
                        status=m


        if not import_match:
#            common.d('Invalid: Import match missing. Status:', str(status))
            return 300+status # import match missing

        if next_as == None: # AS is last in AS path and we do not know my AS
            export_match=True
        else:
            for er in autnum.export_list:
                m=er.match(next_as, pfx, current_aspath, asset_dir, fltrset_dir,
                           routeset_dir, prngset_dir, ipv6)
                if m == 0:
                    export_match=True
                    break
                else:
                    if m>3:
                        status=m

            for er in autnum.mp_export_list:
                m=er.match(next_as, pfx, current_aspath, asset_dir, fltrset_dir,
                           routeset_dir, prngset_dir, ipv6)
                if m == 0:
                    export_match=True
                    break
                else:
                    if m>3:
                        status=m

        if not export_match:
            #common.d('Invalid: Export match missing. Status:', str(status))
            return 400+status # export match missing
    else:
        #common.d('Dunno: ASN not in RIPE region.')
        return 2 # ASN not in RIPE region (=not found in aut-num directory)

    #common.d("Valid. Match.")
    return 0 # otherwise it must have matched both import and export
    


def check_ripe_path(path_vector, autnum_dir, asset_dir, routeset_dir, filterset_dir,
                    prngset_dir, ipv6=False, myas=None):
    """
    Chech path in path vector by means of resolving all aut-num
    object and filters along the as-path in the path_vector from BGP.

    TODO descr
    """
    
    # assert...
    if not path_vector[1].find('/')>0:
        raise Exception("Pfx not normalized: "+str(path_vector))

    aspath = normalize_aspath(path_vector[3])
    status  = []
    allinripe = True

    #common.d('Checking path for ', str(path_vector))
    # go through as-path one by one AS and check routes
    for i,asn in enumerate(aspath):
        previous_as = (aspath[i-1] if i>0 else myas)

        next_as = (aspath[i+1] if i<(len(aspath)-1) else None)
        
        res = check_ripe_path_step(path_vector[1], asn, aspath[i:], previous_as, next_as,
                                   autnum_dir, asset_dir, routeset_dir, filterset_dir, prngset_dir, ipv6)

        if res == 2: # means that the ASN is out of RIPE region
            allinripe = False

#        if res == 0:
#            common.d("Step OK.")
#        else:
#            common.d("Step failed:", str(res))
#
#        status.append((asn, res))

    return (path_vector, allinripe, status)


def check_ripe_paths(day, ianadir, host, ipv6=False, bestonly=True, myas=None, pfx_with_matching_route=None):
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
    300-399 = prevASN not found or prevASN filter failed
    400-499 = nextASN not found or nextASN filter failed  (might be suppressed
    by the status=3xx which has precedecnce but the AS should not export
    prefix that it didnt imported in documented way...)
    """
    # Plan:
    # load BGP dump, aut-num, as-set and *-set pickles
    # pick routes that belongs to RIPE and instead of verifying route
    # object by calling check_ripe_route(path_vector, iana_dir, ripe_routes)
    # just match them in suppliled hash table (this is huge memory optimization)
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

    
    #riperoutes_pkl=(ripe_route6_pickle(day) if ipv6 else ripe_route_pickle(day))
    #riperoutes=common.load_pickle(riperoutes_pkl)
    # Memory optimization. See further.

    asset_dir = common.load_pickle(ripe_asset_pickle(day))
    autnum_dir = common.load_pickle(ripe_autnum_pickle(day))
    filterset_dir = common.load_pickle(ripe_filterset_pickle(day))
    routeset_dir = common.load_pickle(ripe_routeset_pickle(day))
    peeringset_dir = common.load_pickle(ripe_peeringset_pickle(day))

    bgpdump=common.load_pickle(bgp.bgpdump_pickle(day, host, ipv6))

    # Run the check for BGP data of the day
    count = 0
    for path_vector in bgpdump:
        count+=1
        if count % 1000 == 0:
            print 'Progress: %d of %d'%(count, len(bgpdump))
        if bestonly and not (path_vector[0] and '>' in path_vector[0]):
            continue

        #rc = check_ripe_route(path_vector, ianadir, riperoutes)
        #if rc[3] == 0 or rc[3] == 5: # if the route checks in RIPE DB or it is outside of RIPE region
        # memory optimization:
        if path_vector[1] in pfx_with_matching_route:
            yield check_ripe_path(path_vector, autnum_dir, asset_dir, routeset_dir, filterset_dir,
                                  peeringset_dir, ipv6, myas)
        else:
#            common.d("Origin does not match... No point in checking the path.", path_vector)
            status  = [(asn, 0) for asn in normalize_aspath(path_vector[3])]
            if status:
                status[-1] = (status[-1][-1], 1) # 1=route object failure or uncheckable route,
            # either local route or aggregate route generated in some remote location
            yield (path_vector, True, status)



RIPE_PATHS_MATCH_LEGEND = ['Path verification OK', 'Uncheckable (non-RIPE/aggregate/...)', 'Path verification failed']
RIPE_PATHS_MATCH_DET_LEGEND = ['Hops OK', 'Hops UNKNOWN', 'Import NOT FOUND', 'Export NOT FOUND',
                               'Import fltr FAIL', 'Export fltr FAIL']
def report_ripe_paths_day(check_res, day, outdir, ipv6=False):
    """
    Generate meaningful report 
    0 = match (=OK)
    1 = route uncheckable (local or aggregate... =uncheckable)
    2 = ASN outside of RIPE NCC region (=uncheckable)
    300-399 = prevASN not found or prevASN filter failed
    400-499 = nextASN not found or nextASN filter failed  (might be suppressed
    """

    total_pfx=0
    total_pfx_ok=0
    total_pfx_dunno=0
    total_pfx_fail=0
    
    total_hops=0
    total_hops_ok=0
    total_hops_dunno=0
    total_import_notfound=0
    total_export_notfound=0
    total_import_fltrfail=0
    total_export_fltrfail=0
    
    total_pfx=0

    filename=common.resultdir(day)+(RIPE_BGP2PATHS6_TXT if ipv6 else RIPE_BGP2PATHS4_TXT)
    common.d("Generating file", filename)
    with open(filename, 'w') as of:
        for (path_vector, allinripe, status) in check_res:
            of.write(str(path_vector)+(' (RIPE)' if allinripe else ' (world)')+':\n')

            total_pfx += 1
            
            failures = 0
            dunno = False
            for (autnum, s) in status:
                total_hops += 1
                
                ts=None
                if s == 0:
                    total_hops_ok += 1
                    ts = 'OK'

                elif s == 1:
                    total_hops_dunno += 1
                    dunno = True
                    ts = 'LOCAL/AGGR (=dunno)'

                elif s == 2:
                    total_hops_dunno += 1
                    dunno = True
                    ts = 'NON-RIPE'

                elif s == 300:
                    total_import_notfound += 1
                    failures += 1
                    ts = 'import rule not found'

                elif s > 300 and s < 400:
                    total_import_fltrfail += 1
                    failures += 1
                    ts = 'import filter failed'

                elif s == 400:
                    total_export_notfound += 1
                    failures += 1
                    ts = 'export fule not found'

                elif s > 400 and s < 500:
                    total_export_fltrfail += 1
                    failures += 1
                    ts = 'export filter failed'

                else:
                    common.w('Unknown status in report_ripe_path_day: ', str(s))
                    ts = "UNKNOWN"

                of.write('  * '+str(autnum)+' '+ts+'\n')
            of.write('  Failures: '+str(failures)+'\n\n')

            if dunno:
                total_pfx_dunno += 1
            else:
                if failures > 0:
                    total_pfx_fail += 1
                else:
                    total_pfx_ok += 1

        of.write('\n-------------------------------------------\n')
        of.write("%s: %d\n"%('Total prefixes', total_pfx))
        of.write("%s: %d\n"%(RIPE_PATHS_MATCH_LEGEND[0], total_pfx_ok))
        of.write("%s: %d\n"%(RIPE_PATHS_MATCH_LEGEND[1], total_pfx_dunno))
        of.write("%s: %d\n"%(RIPE_PATHS_MATCH_LEGEND[2], total_pfx_fail))
        of.write('\n')
        of.write("%s: %d\n"%('Total hops observed', total_hops))
        of.write("%s: %d\n"%('Total hops valid', total_hops_ok))
        of.write("%s: %d\n"%('Total hops unknown (non-RIPE/aggregate/...)', total_hops_dunno))
        of.write("%s: %d\n"%('Total import filter not-found', total_import_notfound))
        of.write("%s: %d\n"%('Total import filter invalid', total_import_fltrfail))
        of.write("%s: %d\n"%('Total export filter not-found', total_export_notfound))
        of.write("%s: %d\n"%('Total export filter invalid', total_export_fltrfail))

    return ((total_pfx_ok, total_pfx_dunno, total_pfx_fail),
            (total_hops_ok, total_hops_dunno,
             total_import_notfound, total_export_notfound,
             total_import_fltrfail, total_export_fltrfail))



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
        os.path.isfile(ripe_routeset_pickle(d)) and
        os.path.isfile(ripe_peeringset_pickle(d))):
        common.d("Skipping dir", d, "because we have all needed results.")
        return

    common.d("Unpacking file", fn, "for time", d, ".")
    tmpdir=common.unpack_ripe_file(fn)
    common.d("Resulting dir:", tmpdir)
    try:
        # ripe.db.route
        ros=None
        common.d("Parsing", tmpdir+RIPE_DB_ROUTE)
        if os.path.isfile(tmpdir+RIPE_DB_ROUTE):
            ros=RouteObjectDir(tmpdir+RIPE_DB_ROUTE, False)
            common.save_pickle(ros, ripe_route_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_ROUTE)

        # ripe.db.route6
        ros6=None
        common.d("Parsing", tmpdir+RIPE_DB_ROUTE6)
        if os.path.isfile(tmpdir+RIPE_DB_ROUTE6):
            ros6=RouteObjectDir(tmpdir+RIPE_DB_ROUTE6, True)
            common.save_pickle(ros6, ripe_route6_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE6_DB_ROUTE)
                    
        # ripe.db.aut-num
        ao=None
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
            # Add members from members-of in aut-num
            for aok in ao.table.keys():
                for m in ao.table[aok].memberof_list:
                    if m in ass.table:
                        ass.table[m].members.append(aok)
                    else:
                        common.w("Can not append memeber-of ", m, 'from', aok, 'because as-set not found!')
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
            rs=HashObjectDir(tmpdir+RIPE_DB_ROUTESET, RouteSetObject)
            # Add members from members-of in route objects
            for r in ros.enumerateObjs():
                for m in r.members:
                    if m in rs.table:
                        rs.table[m].members.append(r.getKey())

            # Add members from members-of in route6 objects
            for r in ros6.enumerateObjs():
                for m in r.members:
                    if m in rs.table:
                        rs.table[m].mp_members.append(r.getKey())
            common.save_pickle(rs, ripe_routeset_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_ROUTESET)

        # ripe.db.peering-set
        common.d("Parsing", tmpdir+RIPE_DB_PEERINGSET)
        if os.path.isfile(tmpdir+RIPE_DB_PEERINGSET):
            fs=HashObjectDir(tmpdir+RIPE_DB_PEERINGSET, PeeringSetObject)
            common.save_pickle(fs, ripe_peeringset_pickle(d))
        else:
            raise Exception("Missing file "+tmpdir+RIPE_DB_PEERINGSET)


    finally:
        common.d("Removing dir", tmpdir, "expanded from", fn, "for time", d, ".")
        common.cleanup_path(tmpdir)



# Module interface

def module_prepare(data_root_dir):
        """ Prepare datastructures for RPSL module. """
        
        def module_prepare_thread(tasks):
            for t in tasks:
                module_prepare_day(t[0], t[1])

        
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



def module_run_day(day, ianadir, host, bgp_days, ipv6):
    # TODO multithreading
    pass


def module_run(ripe_days, ianadir, host, bgp_days, ipv6):
    """
    Module main interface.
    TODO descr Plan:
    TODO multithreading
    """
    
    route_totals=[]
    route_violators={}
    path_totals=[]
    path_totals_detail=[]
    for d in ripe_days:
        common.d('Working on data for day:', str(d))
        if d in bgp_days: # test if we have BGP data for the day
            # check routes
            pfx_path_check_worthy={}
            res=None
            bgp2routesfn=common.resultdir(d)+(RIPE_BGP2ROUTES6_PICKLE if ipv6 else RIPE_BGP2ROUTES4_PICKLE)
            if not os.path.isfile(bgp2routesfn):
                common.d("Checking routes. Creating file", bgp2routesfn)
                res=list(check_ripe_routes(d, ianadir, host, ipv6, True))
                common.save_pickle(res, bgp2routesfn)
            else:
                res=common.load_pickle(bgp2routesfn)

            # filter violators
            for r in res:
                if r[3]==3 or r[3]==4: # not match or not found
                    route_violators[r[0]] = True

            # filter routes to be checked by path_check
            for r in res:
                if r[3] == 0 or r[3] == 5: # match or non-RIPE (=unknown)
                    pfx_path_check_worthy[r[0]] = True

            route_totals.append(report_ripe_routes_day(res, d, common.resultdir(d), ipv6))

            # free bgp2routes
            del res
            gc.collect()

            # check paths
            bgp2pathsfn=common.resultdir(d)+(RIPE_BGP2PATHS6_PICKLE if ipv6 else RIPE_BGP2PATHS4_PICKLE)
            if not os.path.isfile(bgp2pathsfn):
                common.d("Checking paths. Creating file", bgp2pathsfn)
                res=list(check_ripe_paths(d, ianadir, host, ipv6, True, MY_ASN, pfx_path_check_worthy))
                common.save_pickle(res, bgp2pathsfn)
            else:
                res=common.load_pickle(bgp2pathsfn)

            path_res=report_ripe_paths_day(res, d, common.resultdir(d), ipv6)
            path_totals.append(path_res[0])
            path_totals_detail.append(path_res[1])

        else:
             common.w('Missing BGP data for day %s'%str(d))

    # Graph route totals
    if route_totals:
        common.d("Generating graph with pfx", common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'))
        graph.gen_multilineplot(route_totals, common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'), legend=RIPE_ROUTES_MATCH_LEGEND)

    # Revisit common.resultdir(d)+RIPE_BGP2ROUTES_PICKLE for each day and cross check time to fix
    if route_violators:
        common.d("Crating route timeline...")
        tl=ripe_gen_route_timeline(route_violators.keys(), ripe_days, bgp_days, ipv6)
        report_route_timeline(tl, ipv6)

    # Graph path totals
    if path_totals:
        common.d("Generating graph with pfx", common.resultdir()+'/bgp2paths'+('6' if ipv6 else '4'))
        graph.gen_multilineplot(path_totals, common.resultdir()+'/bgp2paths'+('6' if ipv6 else '4'), legend=RIPE_PATHS_MATCH_LEGEND)

    if path_totals_detail:
        common.d("Generating graph with pfx", common.resultdir()+'/bgp2paths-detail'+('6' if ipv6 else '4'))
        graph.gen_multilineplot(path_totals, common.resultdir()+'/bgp2paths-detail'+('6' if ipv6 else '4'), legend=RIPE_PATHS_MATCH_DET_LEGEND)


# Unit test interface

def main():
#    raise Exception("This test does not work unless special environment is set.")

    testdir='/home/brill/ext/tmp'
    route_testfile=testdir+RIPE_DB_ROUTE
    route6_testfile=testdir+RIPE_DB_ROUTE6
    autnum_testfile=testdir+RIPE_DB_AUTNUM
    asset_testfile=testdir+RIPE_DB_ASSET
    fltrset_testfile=testdir+RIPE_DB_FILTERSET
    routeset_testfile=testdir+RIPE_DB_ROUTESET
    peeringset_testfile=testdir+RIPE_DB_PEERINGSET


    def test_routes():
        ripeRoutes=RouteObjectDir(route_testfile, False)
        # ripeRoutes.tree.dump()
        print str(ripeRoutes.getRouteObjs("2.10.0.0/16"))

        ripeRoutes=RouteObjectDir(route6_testfile, True)
        # ripeRoutes.tree.dump()
        print str(ripeRoutes.getRouteObjs("2a00:1028::/32"))


    def test_autnums():
        ripeAutNums=RpslObject.parseRipeFile(autnum_testfile, AutNumObject)
        for autnum in ripeAutNums:
            print str(autnum)

    def test_assets():
        ripeAsSets=RpslObject.parseRipeFile(asset_testfile, AsSetObject)
        for asset in ripeAsSets:
            print str(asset)

    def test_fltrsets():
        filterSets=RpslObject.parseRipeFile(fltrset_testfile, FilterSetObject)
        for fset in filterSets:
            print str(fset)

    def test_routesets():
        routeSets=RpslObject.parseRipeFile(routeset_testfile, RouteSetObject)
        for rset in routeSets:
            print str(rset)

    def test_peeringsets():
        prngSets=RpslObject.parseRipeFile(peeringset_testfile, PeeringSetObject)
        for pset in prngSets:
            print str(pset)

    def test_autnum():
        class MockupDir(object):
            def __init__(self):
                self.table={}

        autnum_dir=HashObjectDir(autnum_testfile, AutNumObject)
        asset_dir=HashObjectDir(asset_testfile, AsSetObject)
        routeset_dir=MockupDir()
        fltrset_dir=MockupDir()

#        r=check_ripe_path(['>', '1.2.3.0/24', '1 2 3 i'], autnum_dir, asset_dir, routeset_dir, fltrset_dir, False, None)
#        print str(r)
        r=check_ripe_path_step('1.2.3.0/24', 'AS29134', ['AS1', 'AS2', 'AS8422', 'AS29134'], 'AS16246', 'AS8422', # from AS16246 to AS8422
                               autnum_dir, asset_dir, routeset_dir, fltrset_dir, False)
        print str(r)


    def test_filters():
        # TODO filter tests
        pass
    

#    test_routes()
#    test_autnums()
#    test_assets()
#    test_fltrsets()
#    test_routesets()
    test_peeringsets()
    test_autnum()
    test_filters()


if __name__ == '__main__':
    main()
