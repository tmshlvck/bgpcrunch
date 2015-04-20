#!/usr/bin/python
#
# BGPcrunch - BGP analysis toolset
# (C) 2014 Tomas Hlavacek (tmshlvck@gmail.com)
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

import common
import ianaspace
import cisco

class RpslObject(object):
    def __init__(self,textlines):
        self.text=textlines


class RouteObject(RpslObject):
    ROUTE_ATTR = 'route'
    ORIGIN_ATTR = 'origin'
    def __init__(self,textlines):
        self.route=None
        self.origin=None
        
        for l in textlines:
            gr=l.split(':',1)
            if gr[0]==self.ROUTE_ATTR:
                self.route=str(gr[1]).strip()
            elif gr[0]==self.ORIGIN_ATTR:
                self.origin=str(gr[1]).strip()

            if self.route and self.origin:
                break

        if not (self.route and self.origin):
            raise Exception("Can not create RouteObject out of text: "+str(textlines))


def parse_route_objects(filename):
    def flushobj(ot):
        if ot:
            try:
                return RouteObject(ot)
            except Exception as e:
                common.debug("Route object parse exception: "+str(e))
    
    with open(filename, 'r') as sf:
        objecttext=[]
        for l in sf.readlines():
            l=l.strip()
            if l=='':
                o=flushobj(objecttext)
                if o:
                    yield o
                
                objecttext=[]
            else:
                objecttext.append(l)

        o=flushobj(objecttext)
        if o:
            yield o



class AutNumObject(RpslObject):
    def __init__(self,textlines):
        pass

# HACK HACK HACK TODO normalize + tree + remove duplication
def getroute(routeobjects,prefix):
    def normalize_addr(addr):
        s=addr.split('.')
        r=''
        for i,af in enumerate(s):
            r+=str(int(af))
            if i!=len(s)-1:
                r+='.'

        if len(s) < 4:
            r +='.0'*(4-len(s))
        return r

    def resolve_mask(addr):
        f=int(addr.split('.')[0])
        if f >= 224:
            raise Exception("Can not resolve mask for D or E class.")
                
        if f <= 127:
            return 8
        elif f <= 191:
            return 16
        else:
            return 24


    def normalize_ipv4_prefix(pfx):
        a=''
        m=''

        s=pfx.split('/')
        if len(s) == 2:
            a = normalize_addr(s[0])
            m = int(s[1])
        else:
            a = normalize_addr(pfx)
            m = resolve_mask(a)

        return str(a)+'/'+str(m)

    res=[]
    for o in routeobjects:
        if str(normalize_ipv4_prefix(prefix)) == str(o.route):
            res.append(o)
    return res

# TODO: replace getroute with tree, support IPv6
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
    



def daily_stats(time,rpsldir,):
    check_ripe_routes(time,rpsldir,False)
    

    
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




def main():
    riperoutes=parse_route_objects("/tmp/bgpcrunch45O5jU"+"/ripe.db.route")
    getroute(riperoutes,"2.10.0.0/16")
    return
    
    for o in parse_route_objects(sys.argv[1]):
        print "O: "+str(o.route)+" -> "+str(o.origin)
        


if __name__ == '__main__':
    main()
