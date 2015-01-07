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


# Constants

DEBUG=False

ROOT_DIR='/home/brill/projects/bgpcrunch'
DATA_DIR=ROOT_DIR+'/data'
RESULT_DIR=ROOT_DIR+'/results'
SCRIPTS_DIR=ROOT_DIR+'/scripts'
BGP_DATA={'marge':DATA_DIR+'/marge',}
BGP_HOSTS=['marge']
RIPE_DATA=DATA_DIR+'/ripe'
TMPDIR_PREFIX='bgpcrunch'

BIN_TAR='/bin/tar'











# Exported functions

def debug(m):
    if DEBUG:
        sys.stderr.write(m+"\n")


PREFIX_REGEXP=re.compile("[0-9a-fA-F:\.]+/([0-9]{1,3})")
def get_pfxlen(pfx):
    """
    Resolve netmask for an IPv4 or IPv6 prefix.

    When the prefix is IPv6 it has to contain explicit prefix length. I.E. 2001:1::/32 -> 32
    When the IPv4 prefix contains explicit netmask it just returns it. I.E. 1.2.3.4/24 -> 24
    Netmask is determined based on classful IPv4 split otherwise.

    pfx: IP address as string.
    returns: (Int) Netmask.
    """
    if pfx.strip() == '0.0.0.0':
        return 0

    m=PREFIX_REGEXP.match(pfx)
    if m:
        return int(m.group(1))
    else:
        f=int(pfx.split(".")[0])
        if f <= 127:
            return 8
        elif f<= 191:
            return 16
        elif f<= 239:
            return 24
        else:
            raise Exception("Multicast or reserved address hit: "+pfx)

def get_bgp_pathlen(p):
    return (len(p.split(' '))-1)


def parse_bgp_filename(filename):
    # Input filename='bgp-ipv6-2014-2-16-1-17-2.txt.bz2'
    # Output (ipv6,year,month,day,hour,min,sec)

    ipv6=False

    g=filename.split('-')
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


def enumerate_available_times(ipv6):
    times=[]
    for host in BGP_HOSTS:
        for dirname, dirnames, filenames in os.walk(BGP_DATA[host]):
            # change in 'dirnames' will stop os.walk() from recursing into there.
            if '.git' in dirnames:
                dirnames.remove('.git')
                continue

            for filename in filenames:
                meta=parse_bgp_filename(filename)
                if meta[0] == ipv6:
                    times.append(meta[1:])
    return times
                        

def is_same_day(time1,time2):
    if time1[0] == time2[0] and time1[1] == time2[1] and time1[2] == time2[2]:
        return True
    else:
        return False


def get_bgp_file(time,ipv6):
    for host in BGP_HOSTS:
        for dirname, dirnames, filenames in os.walk(BGP_DATA[host]):
            # change in 'dirnames' will stop os.walk() from recursing into there.
            if '.git' in dirnames:
                dirnames.remove('.git')
                continue

            for filename in filenames:
                meta=parse_bgp_filename(filename)
                if meta[0] == ipv6 and is_same_day(time,meta[1:]):
                    return dirname+'/'+filename


def get_ripe_file(time):
    for dirname, dirnames, filenames in os.walk(RIPE_DATA):
        # change in 'dirnames' will stop os.walk() from recursing into there.
        if '.git' in dirnames:
            dirnames.remove('.git')
            continue

        for filename in filenames:
            meta=parse_bgp_filename(filename)
            if is_same_day(time,meta[1:]):
                return filename


def unpack_ripe_file(filename):
    dir=tempfile.mkdtemp(prefix=TMPDIR_PREFIX)
    d('mktempdir: '+dir)
    d(BIN_TAR+' jxf '+filename+' -C '+dir)
    os.system(BIN_TAR+' jxf '+filename+' -C '+dir)
    return dir


def cleanup_path(path):
    d('Cleaning up path '+path)
    os.system(BIN_RM+' -rf '+path)


def get_result_dir(time):
    rd=RESULT_DIR+'/'+str(time[0])+'-'+str(time[1])+'-'+str(time[2])

    if not (os.path.exists(rd) and os.path.isdir(rd)):
        os.mkdir(rd)

    return rd


def get_text_fh(filename):
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
