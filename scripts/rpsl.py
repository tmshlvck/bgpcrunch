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








def main():
    for o in parse_route_objects(sys.argv[1]):
        print "O: "+str(o.route)+" -> "+str(o.origin)
        


if __name__ == '__main__':
    main()
