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
import ianaspace
import cisco

class RpslObject(object):
    def __init__(self,textlines):
        self.text=textlines

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
        self._initTree(RpslObject.parseRipeFile(filename,RouteObject),ipv6)

    def _initTree(self,routeobjects,ipv6):
        """ routeobjects is supposedly a generator... """
        self.tree=common.IPLookupTree(ipv6)
        for o in routeobjects:
            self.tree.add(o.route,o)
            if not o.origin in self.originTable:
                self.originTable[o.origin]=[]
            self.originTable[o.origin].append(o)


    def getRouteObjs(self, prefix):
        return self.tree.lookupAllLevels(prefix)



######################

class AutNumObject(RpslObject):
    def __init__(self,textlines):
        pass









######################################################################



def check_ripe_routes(time,rpsldir,ipv6=False,bestonly=True):
    idir = ianaspace.IanaDirectory(ipv6)
    riperoutes=None
    if ipv6:
        raise Exception("IPv6 not supported yet")
    else:
        riperoutes=list(parse_route_objects(rpsldir+"/ripe.db.route"))

    bgpdump=cisco.parse_cisco_bgp_time(time,ipv6)
    for pv in bgpdump:
        if bestonly and not (pv[0] and '>' in pv[0]):
            continue

        if len(pv[3].split(' '))>2:
            origin=pv[3].split(' ')[-2]
        else:
            continue # localy originated prefix?

        iananet=idir.resolve_network(pv[1])
        if iananet[2] == 'RIPE NCC':
            routes=getroute(riperoutes,pv[1])
            if routes:
                match=False
                for route in routes:
                    if route.origin.upper() == "AS"+origin:
                        print "Route object match "+str(route.route)+"->("+str(route.origin)+")"
                        match=True
                if not match:
                    print "Route object NOT match "+str(route.route)+"->("+str(route.origin)+") found for "+str(pv[1])+" from AS"+str(origin)
            else:
                print "No route object found for "+str(pv[1])
        else:
            print "Skipping non-RIPE NCC network "+pv[1]+" which is part of "+str(iananet[0])+" ("+str(iananet[2])+")"
    


    

    
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

def module_prepare(srcdir, dstdir):
    """
    Prepare crunched RIPE DB for a day. In most cases it means parsing
    text files, crating proper data structures and saving them as pickle files.
    """

    ripe_routes_sourcefile=srcdir+'/ripe.db.route'
    ripe_routes_dstfile=dstdir+'/ripe.route.pickle'

    if os.path.isfile(ripe_routes_sourcefile):
        ros=RouteObjectDir(ripe_routes_sourcefile, False)
        common.save_pickle(ros, ripe_routes_dstfile)
    else:
        raise Exception("Missing file "+ripe_routes_sourcefile)

    # TODO: Create directories for AutNums && InetNums && AS-Sets


def module_run():
    # check_ripe_routes(...)
    
    pass


def main():
    # raise Exception("This test does not work unless special environment is set.")

    ripeRoutes=RouteObjectDir("/tmp/bgpcrunchVs4aOl"+"/ripe.db.route", False)
    # ripeRoutes.tree.dump()
    print str(ripeRoutes.getRouteObjs("2.10.0.0/16"))
    return


if __name__ == '__main__':
    main()
