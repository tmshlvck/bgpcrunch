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
 

import sys
import re

import common
import cisco


def get_buckets(lines=[],ipv6=False):
    # Returns buckets (= list of numbers where
    # buckets[pfx_len]=number_of_prefixes_of_the_len).
    # lines - list of input lines
    # ipv6 - bool
    # Returns list of ints.

    i=0
    r=0
    print "Cisco run"
    matched=cisco.matchCiscoBGP(lines)
    print "Cisco done"
    result=[]
    for (i,m) in enumerate(matched):
        if m[1] == '':
            m[1]=matched[i-1][1]
        
        if m[0].find('>') >= 0: # best route
            result.append(m)


    buckets=[]
    rng=32
    if ipv6:
        rng=128

    for i in range(0,rng+1):
        buckets.append([])

    for r in result:
        nm = common.get_pfxlen(r[1])
        common.debug("nm="+str(nm)+" p="+str(r[1]))
        try:
            buckets[nm].append(common.get_bgp_pathlen(r[6]))
        except:
            print "EXC: nm="+str(nm)+" r[6]="+str(r)

    return buckets

def format_buckets(buckets):
    # Returns textual representation of buckets.
    # buckets - list of ints.
    # Returns list of lines.
    
    lines=[]
    tpfx=0
    lines.append("Avg path length by prefixlength:")
    for (i,b) in enumerate(buckets):
        pc=len(b)
        tpfx+=pc

        pl=0
        for l in b:
            pl+=l
        if pc == 0:
            lines.append("/"+str(i)+" : N/A (0 prefixes)")
        else:
            lines.append("/"+str(i)+" : "+str(float(pl)/pc)+" ("+str(pc)+" prefixes)")

    lines.append("Total prefixes examined: "+str(tpfx))
    return lines


def get_buckets_from_file_old(filename,ipv6=False):
    filedesc = sys.stdin
    if filename:
        filedesc=common.get_text_fh(filename)

    return get_buckets(filedesc.readlines(),ipv6)





def parse_cisco_bgp(filename=None):
    HEADER_REGEX=re.compile('^.+ (Next Hop) .+ (Path).*$')
    LINE_START_REGEX=re.compile('\s*([>isdhRSfxacmb\*]*)(\s+.*)?')
    ADDR_REGEX=re.compile('(.*\s)?([a-fA-F0-9]{0,4}:[a-fA-F0-9:]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(\s+.*)?')
    PREFIX_REGEX=re.compile('([>isdhRSfxacmb\s\*]*\s+)?([a-fA-F0-9]{0,4}:[a-fA-F0-9:]+[/0-9]{0,4}|([0-9.]{1,4}){1,4}[/0-9]{0,3})(\s+.*)?')
    WHITE_REGEX=re.compile('\s')
    
    filedesc = sys.stdin
    if filename:
        filedesc=common.get_text_fh(filename)

    nhbeg=None
    apbeg=None

    indicator=None
    pfx=None
    nexthop=None
    aspath=None

    for l in filedesc.readlines():
        l=l.rstrip()
#        print "L "+l
        if nhbeg==None and apbeg==None:
            m=HEADER_REGEX.match(l)
            if m:
                nhbeg=m.start(1)
                apbeg=m.start(2)
            continue

        else:
            m=LINE_START_REGEX.match(l)
            if m and len(m.group(1))>0:
                indicator=m.group(1)

            m=PREFIX_REGEX.match(l)
            if m and m.start(2)<nhbeg:
                pfx=m.group(2)

            m=ADDR_REGEX.match(l)
            if m and m.start(2)>=nhbeg:
                nexthop=m.group(2)

            if len(l)>apbeg and WHITE_REGEX.match(l[apbeg-1]):
                aspath=l[apbeg:]
                yield (indicator,pfx,nexthop,aspath)

            if len(l)>apbeg and WHITE_REGEX.match(l[apbeg]):
                aspath=l[apbeg+1:]
                yield (indicator,pfx,nexthop,aspath)




def get_buckets_from_file(filename,ipv6=False):
    buckets=[]
    rng=32
    if ipv6:
        rng=128

    for i in range(0,rng+1):
        buckets.append([])

    for r in parse_cisco_bgp(filename):
        nm = common.get_pfxlen(r[1])
        common.debug("nm="+str(nm)+" p="+str(r[1]))
        try:
            buckets[nm].append(common.get_bgp_pathlen(r[3]))
        except:
            print "EXC: nm="+str(nm)+" r[6]="+str(r)

    return buckets










      

def main():
    ipv6=False
    if len(sys.argv)>1 and sys.argv[1]=='-6':
        ipv6=True

    filename=None
    if len(sys.argv)>2:
        filename=sys.argv[2]

    b=get_buckets_from_file(filename,ipv6)
    for l in format_buckets(b):
        print l


if __name__ == "__main__":
#    main()
    import cProfile
    cProfile.run('main()')
