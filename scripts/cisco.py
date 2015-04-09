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
import os
import cPickle as pickle

import common


def parse_cisco_bgp_file(filename=None):
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


def parse_cisco_bgp_time(t,ipv6=False):
    infile=common.get_bgp_file(t,ipv6)
    resultdir=common.get_result_dir(t)
    outfile=resultdir+'/bgpdump'+('6' if ipv6 else '4')+'.pkl'
    
    o=None
    if os.path.isfile(outfile):
        if not os.path.isfile(infile):
            common.warn("No infile for outfile "+outfile)

        common.debug("Loading pickle file "+outfile)
        with open(outfile, 'rb') as input:
            o = pickle.load(input)
        return o
        

    o=list(parse_cisco_bgp_file(infile))
    common.debug("Saving pickle file "+outfile)
    with open(outfile, 'wb') as output:
        pickle.dump(o, output, pickle.HIGHEST_PROTOCOL)

    return o
