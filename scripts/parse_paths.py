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

def format_buckets(buckets):
    """
    Returns textual representation of buckets.
    buckets - list of ints.
    Returns list of lines.
    """
    
    tpfx=0
    yield "Avg path length by prefixlength:"
    for (i,b) in enumerate(buckets):
        pc=len(b)
        tpfx+=pc

        pl=0
        for l in b:
            pl+=l
        if pc == 0:
            yield "/"+str(i)+" : N/A (0 prefixes)"
        else:
            yield "/"+str(i)+" : "+str(float(pl)/pc)+" ("+str(pc)+" prefixes)"

    yield "Total prefixes examined: "+str(tpfx)


def parse_cisco_bgp(filename=None):
    """
    Read Cisco show ip bgp output captured in a file (specified by
    the filename) and returns tuples (indicator,pfx,nexthop,aspath).
    filename - string
    Returns generator that generates [(indicator,pfx,nexthop,aspath),...]
    """
    
    HEADER_REGEX=re.compile('^.+ (Next Hop) .+ (Path).*$')
    LINE_START_REGEX=re.compile('\s*([>isdhRSfxacmb\*]*)([0-9\s].*)?')
    ADDR_REGEX=re.compile('(.*\s)?([a-fA-F0-9]{0,4}:[a-fA-F0-9:]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(\s+.*)?')
    PREFIX_REGEX=re.compile('([>isdhRSfxacmb\s\*]*[i\s]+)?([a-fA-F0-9]{0,4}:[a-fA-F0-9:]+[/0-9]{0,4}|([0-9.]{1,4}){1,4}[/0-9]{0,3})(\s+.*)?')
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
                indicator=None

            if len(l)>apbeg and WHITE_REGEX.match(l[apbeg]):
                aspath=l[apbeg+1:]
                yield (indicator,pfx,nexthop,aspath)
                indicator=None




def get_buckets_from_file(filename,ipv6=False,bestonly=False):
    """
    Reads Cisco show ip bgp output captured in a file and returns
    list of lists of path length where:
    r=get_buckets_from_file(...)
    r[16]=[x,y,z,...] ; x,y,z are strings. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...

    filename - string
    ipv6 - bool (=expect /128 masks)
    bestonly - ignore received but not used routes
    """
    
    buckets=[]
    rng=32
    if ipv6:
        rng=128

    for i in range(0,rng+1):
        buckets.append([])

    for r in parse_cisco_bgp(filename):
        if bestonly and not (r[0] and '>' in r[0]):
            continue
        
        nm = common.get_pfxlen(r[1])
        try:
            buckets[nm].append(common.get_bgp_pathlen(r[3]))
        except:
            print "EXC: nm="+str(nm)+" r[6]="+str(r)

    return buckets



import getopt,sys
def main():
    def usage():
        print """analyze_bgp.py [-6] [-f filename] -- generate histogram from a captured
Cisco show ip bgp or show ipv6 bgp
  -6 : expect show ipv6 bgp instead of show ip bgp capture
  -f filename : analyze filename instead of stdin
"""
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h6f:')
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)
    
    ipv6=False
    filename=None
    for o,a in opts:
        if o == '-6':
            ipv6=True
        elif o == '-f':
            filename = a
        elif o == 'h':
            usage()
            sys.exit(0)
        else:
            usage()
            sys.exit(2)


    b=get_buckets_from_file(filename,ipv6,True)
    for l in format_buckets(b):
        print l


if __name__ == "__main__":
    main()
