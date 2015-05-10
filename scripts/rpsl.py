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

import common
import graph
import ianaspace
import bgp


RIPE_DB_ROUTE='/ripe.db.route'
RIPE_DB_ROUTE_PICKLE='/ripe.route.pickle'
RIPE_DB_ROUTE6_PICKLE='/ripe.route6.pickle'
RIPE_BGP2ROUTES4_TXT='/bgp2routes.txt'
RIPE_BGP2ROUTES4_PICKLE='/bgp2routes.pickle'
RIPE_BGP2ROUTES6_TXT='/bgp2routes.txt'
RIPE_BGP2ROUTES6_PICKLE='/bgp2routes.pickle'

class RpslObject(object):
    def __init__(self,textlines):
        self.text=textlines

    def splitLines(self):
        """ Returns generator of tuples (attribute,value) and discards comments. """

        buf=('','')
        for l in self.text:
            # Discard comments
            c = l.find('#')
            if c >= 0:
                l = l[:c]

            if l.strip() == '':
                continue

            if buf:
                if not (l[0].isspace() or l[0]=='+' ):
                    yield buf
                else:
                    buf=(buf[0],str(buf[1]+' '+l[1:].strip()).strip())
                    continue


            # Find attr and value
            gr=l.strip().split(':',1)
            if len (gr) != 2:
                raise Exception("Can not parse line: "+l)

            buf=(gr[0].strip(), gr[1].strip())

        yield buf

    @staticmethod    
    def parseRipeFile(filename, targetClass):
        """ Parse RIPE object file of a targetClass. Theoretically more
        types might be  supported and modifier to __init__ of each class
        has to be created. """
        def flushrobj(ot):
            if ot:
                try:
                    return targetClass(ot)
                except Exception as e:
                    common.w("Object parse exception: "+str(e))
    
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


class RouteObject(RpslObject):
    ROUTE_ATTR = 'route'
    ORIGIN_ATTR = 'origin'
    def __init__(self,textlines):
        RpslObject.__init__(self,textlines)
        self.route=None
        self.origin=None

        for (a,v) in self.splitLines():
            if a==self.ROUTE_ATTR:
                self.route=v
            elif a==self.ORIGIN_ATTR:
                if v.lower()[:2] == 'as':
                    self.origin=int(v[2:].strip())
                else:
                    raise Exception("Can not parse tuple "+a+":"+v)

            # TODO: Add holes
            if self.route and self.origin:
                break

        if not (self.route and self.origin):
            raise Exception("Can not create RouteObject out of text: "+str(textlines))

    def __str__(self):
        return 'RouteObject: '+str(self.route)+'->'+str(self.origin)

    def __repr__(self):
        return self.__str__()


class RouteObjectDir(object):
    def __init__(self,filename,ipv6=False):
        self.originTable={}
        self._initTreeAndTable(RpslObject.parseRipeFile(filename,RouteObject),ipv6)

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



class AutNumObject(RpslObject):
    def __init__(self,textlines):
        pass









######################################################################


# File handling

def ripe_route_pickle(day):
    return common.resultdir(day)+RIPE_DB_ROUTE_PICKLE

def ripe_route6_pickle(day):
    return common.resultdir(day)+RIPE_DB_ROUTE6_PICKLE


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



# Checking code


def check_ripe_routes(day, ianadir, host, bgp_days, ipv6=False, bestonly=True):
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
    for pv in bgpdump:
        if bestonly and not (pv[0] and '>' in pv[0]):
            continue

        # assert...
        if not pv[1].find('/')>0:
            raise Exception("Pfx not normalized: "+str(pv))
        ################

        if len(pv[3].split(' '))>=2:
            orig=pv[3].split(' ')[-2]
            if orig.find("{")>=0:
                #common.d("Skipping prefix with aggregated begining of ASpath:", orig)
                res.append((pv[1],pv[3],None,1))
                continue
        else:
            # localy originated prefix?
            common.w('Skipping prefix with less than 2 records in ASpath: ', pv)
            res.append((pv[1],pv[3],None,2))
            continue

        iananet=ianadir.resolve_network(pv[1])
        if iananet[2] == 'RIPE NCC':
            routes=riperoutes.getRouteObjs(pv[1])
            if routes:
                match=False
                for r in routes:
                    if r.origin == int(orig):
                        #common.d("Route object match for", pv[1], '('+pv[3]+"):", str(r))
                        res.append((pv[1],pv[3],r,0))
                        match=True
                        break
                if not match:
                    common.d("Route object NOT match", str(r.route), "("+str(r.origin)+") found for", str(pv[1]), "from AS"+str(orig))
                    res.append((pv[1],pv[3],None,3))
            else:
                #common.d("No route object found for", str(pv[1]))
                res.append((pv[1],pv[3],None,4))
        else:
            #common.d("Skipping non-RIPE NCC network", pv[1], "which is part of", str(iananet[0]), "("+str(iananet[2])+")")
            res.append((pv[1],pv[3],None,5))

    return res




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

    

# TODO    
def create_ripe_objectdb_stats():
        for t in list(set(common.enumerate_available_times(False)) |
                      set(common.enumerate_available_times(True))):
#                ripefile = common.get_ripe_file(t)
#                if not ripefile:
#                        common.debug("Skipping RPSL parse for time "+str(t)+". No DB snapshot available.")
#                        continue
                
#                common.debug("Processing time "+str(t)+"...")
#                common.debug("RIPE file: "+str(ripefile))

#                rpsldir=common.unpack_ripe_file(ripefile)
#                common.debug("RIPE unpack result: "+rpsldir)

                rpsldir = "/tmp/bgpcrunch45O5jU"
                daily_stats(t,rpsldir)
                
#                common.cleanup_path(rpsldir)






# Module interface

def module_prepare(data_root_dir):
        """ Prepare datastructures for RPSL module. """
        out_days = []

        for fn in common.enumerate_files(data_root_dir+'/ripe','ripedb-[0-9-]+\.tar\.bz2'):
                d = common.Day(decode_ripe_tgz_filename(fn)[0:3])
                out_days.append(d)

                # skip parsed days (enumerate all needed results)
                if os.path.isfile(ripe_route_pickle(d)):
                    continue

                common.d("Unpacking file", fn, "for time", d, ".")
                tmpdir=common.unpack_ripe_file(fn)
                common.d("Resulting dir:", tmpdir)
                try:
                    # ripe.db.route
                    if os.path.isfile(ripe_routes_sourcef):
                        ros=RouteObjectDir(tmpdir+RIPE_DB_ROUTE, False)
                        common.save_pickle(ros, ripe_route_pickle(d))
                    else:
                        raise Exception("Missing file "+ripe_routes_sourcefile)

                    # TODO: Create directories for AutNums && InetNums && AS-Sets

                finally:
                        common.d("Removing dir", tmpdir, "expanded from", fn, "for time", d, ".")
                        common.cleanup_path(tmpdir)

        return out_days



def module_run(ripe_days, ianadir, host, bgp_days, ipv6):
    common.d("rpsl.module_run ripe_days:", ripe_days)
    common.d("rpsl.module_run bgp_days:", bgp_days)

    route_totals=[]
    for d in ripe_days:
        if d in bgp_days: # test if we have BGP data for the day
            res=None
            bgp2routesfn=common.resultdir(d)+(RIPE_BGP2ROUTES6_PICKLE if ipv6 else RIPE_BGP2ROUTES4_PICKLE)
            if not os.path.isfile(bgp2routesfn):
                res=check_ripe_routes(d, ianadir, host, bgp_days, ipv6, True)
                common.save_pickle(res, bgp2routesfn)
            else:
                res=common.load_pickle(bgp2routesfn)

            route_totals.append(report_ripe_routes_day(res, d, common.resultdir(d), ipv6))

            # TODO check_paths

        else:
             common.w('Missing BGP data for day %s'%str(d))

    # Graph totals
    if route_totals:
        common.d("Generating graph with pfx", common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'))
        graph.gen_multilineplot(route_totals, common.resultdir()+'/bgp2routes'+('6' if ipv6 else '4'), legend=RIPE_ROUTES_MATCH_LEGEND)

    #TODO:
    #revisit common.resultdir(d)+RIPE_BGP2ROUTES_PICKLE for each day and cross check time to fix




# Unit test interface

def main():
    raise Exception("This test does not work unless special environment is set.")

    ripeRoutes=RouteObjectDir("/tmp/bgpcrunchVs4aOl"+"/ripe.db.route", False)
    # ripeRoutes.tree.dump()
    print str(ripeRoutes.getRouteObjs("2.10.0.0/16"))
    return


if __name__ == '__main__':
    main()
