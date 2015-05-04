#!/usr/bin/python
#
# BGPcrunch - BGP analysis toolset
# (C) 2012-2015 Tomas Hlavacek (tmshlvck@gmail.com)
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


def _get_text_fh(filename):
    """ Open gzip/bz2 and uncompressed files seamlessly based on suffix. """
    
    def unbz2(filename):
        import bz2
        return bz2.BZ2File(filename)

    def ungz(filename):
        raise Exception('.gz unsupported at the moment')
    
    if re.match('.*\.bz2$', filename):
        return unbz2(filename)
    elif re.match('.*\.gz$', filename):
        return ungz(filename)
    else:
        return open(filename,'r')



def parse_cisco_bgp_file(filename=None,ipv6=False):
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
        filedesc=_get_text_fh(filename)

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
                if not ipv6:
                    pfx=common.normalize_ipv4_prefix(pfx)

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



def load_bgp_pickle(filename):
    """ Load Cisco show ip bgp output captured and transformed to
    a pickle file that contains list of tuples from parse_cisco_bgp_file.
    """

    o=None
    common.d("Loading pickle file", filename)
    with open(filename, 'rb') as input:
        o = pickle.load(input)
    return o



def gen_bgp_pickle(infile,outfile,ipv6=False):
    """ Read Cisco show ip bgp output captured in a infile
    and generate outfile (pickle that contains list of tuples
    that parse_cisco_bgp_file returns).

    infile: in filename (prefferably full path to the BGP text file)
    outfile: out filename
    ipv6: IPv6 indicator (needed for prefix normalization)
    """

    if os.path.isfile(outfile):
        return load_bgp_pickle(outfile)
    
    o=list(parse_cisco_bgp_file(infile, ipv6))
    common.d("Saving pickle file "+outfile)
    with open(outfile, 'wb') as output:
        pickle.dump(o, output, pickle.HIGHEST_PROTOCOL)

    return o

