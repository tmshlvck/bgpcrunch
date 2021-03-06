#!/usr/bin/python
#
# BGPcrunch - BGP analysis toolset
# Copyright (C) 2014-2015 Tomas Hlavacek (tmshlvck@gmail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# 

import re
import sys
import os

import common


def _get_text_fh(filename):
    """ Open gzip/bz2 and uncompressed files seamlessly based on suffix.
    
    :param str filename: File name to process
    :returns: Open file descriptor that can be directly read
    """
    
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
    """ Read Cisco show ip bgp output captured in a file (specified by
    the filename) and returns tuples (indicator,pfx,nexthop,aspath).
    
    :param str filename: string - The file name to parse.
    :returns: Iterator that generates [(indicator,pfx,nexthop,aspath),...]
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



def gen_bgpdump_pickle(infile,outfile,ipv6=False):
    """ Read Cisco show ip bgp output captured in a infile
    and generate outfile (pickle that contains list of tuples
    that parse_cisco_bgp_file returns).

    :param str infile: Input filename (prefferably full path to the BGP text file)
    :param str outfile: Output filename
    :param bool ipv6: IPv6 indicator (needed for prefix normalization)
    :returns: The parsed cisco bgp output either from pickle or from the primary source
    """

    if os.path.isfile(outfile):
        return common.load_pickle(outfile)
    
    o=list(parse_cisco_bgp_file(infile, ipv6))

    common.save_pickle(o, outfile)

    return o

