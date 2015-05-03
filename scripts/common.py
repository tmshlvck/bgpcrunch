#!/usr/bin/env python
#
# BGPCRUNCH - BGP analysis toolset
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
import os
import tempfile
import operator

import ipaddr


# Constants

DEBUG=True


BIN_TAR='/bin/tar'
BIN_RM='/bin/rm'











# Exported functions

def d(m,*args):
    """ Print debug message. d('fnc_x dbg x=',1,'y=',2) """

    if DEBUG:
        for a in args:
            m += ' '+str(a)
        sys.stderr.write(m+"\n")

def w(m):
    """ Print warning message. d('fnc_x dbg x=',1,'y=',2) """
    sys.stderr.write(m+"\n")


def enumerate_files(dir,pattern):
        """
        Enumerate files in a directory that matches the pattern.
        Returns iterator that returns filenames with full path.
        """

        regex = re.compile(pattern)
        for f in os.listdir(dir):
                if regex.match(f):
                        yield os.path.abspath(dir+'/'+f)


def parse_bgp_filename(filename):
    """
    Input filename='bgp-ipv6-2014-2-16-1-17-2.txt.bz2'
    Output (ipv6,year,month,day,hour,min,sec)
    """

    ipv6=False

    basename=os.path.basename(filename)
    g=basename.split('-')
    if g[0] != 'bgp':
        raise Exception('Can not parse filename: '+filename)
    if g[1] == 'ipv6':
        ipv6=True
    elif g[1] == 'ipv4':
        ipv6=False
    else:
        raise Exception('Can not parse filename: '+filename)

    g[7]=g[7].split('.',1)[0]

    return (ipv6,int(g[2]),int(g[3]),int(g[4]),int(g[5]),int(g[6]),int(g[7]))


def parse_ripe_filename(filename):
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


def checkcreatedir(dir):
    if not (os.path.exists(dir) and os.path.isdir(dir)):
        os.mkdir(dir)

    return dir
                        





###########################




    

def unpack_ripe_file(filename):
    dir=tempfile.mkdtemp(prefix=TMPDIR_PREFIX)
    debug('mktempdir: '+dir)
    debug(BIN_TAR+' jxf '+filename+' -C '+dir)
    os.system(BIN_TAR+' jxf '+filename+' -C '+dir)
    return dir


def cleanup_path(path):
    debug('Cleaning up path '+path)
    os.system(BIN_RM+' -rf '+path)



# Exported classes


class Day(object):
    def __init__(self,time_tuple=None):
        if time_tuple:
            self.setTime(time_tuple)

    def setTime(self,time_tuple):
        if len(time_tuple) != 3:
            raise Exception("time_tuple must contain (year,month,day)")
        try:
            int(time_tuple[0])
            int(time_tuple[1])
            int(time_tuple[2])
        except:
            raise Exception("time_tuple must contain three integers")

        self.time = time_tuple

    def __str__(self):
        return ("%04d" % self.time[0])+'-'+("%02d" % self.time[1])+'-'+("%02d" % self.time[2])

    def __repr__(self):
        return self.__str__()

    def __eq__(self,other):
        return (self.time == other.time)


class IPLookupTree(object):
    class IPLookupTreeNode:
        def __init__(self):
            self.one=None
            self.zero=None
            self.end=None
            self.data=None

    
    def __init__(self,ipv6=False):
        self.ipv6=ipv6
        self.root=IPLookupTree.IPLookupTreeNode()

    def _bits(self,chararray):
        for c in chararray:
            ct=ord(c)
            for i in range(7,-1,-1):
                if ct & (1 << i):
                    yield True
                else:
                    yield False

    def add(self,net,data):
        if not (isinstance(net, ipaddr.IPv4Network) or isinstance(net, ipaddr.IPv6Network)):
            net = ipaddr.IPNetwork(net)

        bits = list(self._bits(net.packed))
        index=self.root
        for bi in range(0,net.prefixlen):
            if bits[bi]:
                if not index.one:
                    index.one = self.IPLookupTreeNode()
                index = index.one
            else:
                if not index.zero:
                    index.zero = self.IPLookupTreeNode()
                index = index.zero
        index.end = net
        index.data = data

    def lookupFirst(self,ip):
        limit=128 if self.ipv6 else 32
        if isinstance(ip, ipaddr.IPv4Network) or isinstance(ip, ipaddr.IPv6Network):
            limit=ip.prefixlen

        index = self.root
        for (bi,b) in enumerate(self._bits(ip.packed)):
            if bi > limit:
                return None

            if index.end and ip in index.end: # match
                return index.data

            if b:
                index = index.one
            else:
                index = index.zero

        return None
