#!/usr/bin/env python
#
# BGPCRUNCH - BGP analysis toolset
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


import sys
import re
import os
import tempfile
import cPickle as pickle
import ipaddr


# Constants

DEBUG=True


BIN_TAR='/bin/tar'
BIN_RM='/bin/rm'











# Exported functions

def d(m,*args):
    """ Print debug message. i.e. d('fnc_x dbg x=',1,'y=',2)
    
    :param str m: Text message
    :param args: Additional stringifiable parts of the message.
    """

    if DEBUG:
        for a in args:
            m += ' '+str(a)
        sys.stderr.write(m+"\n")

def w(m,*args):
    """ Print warning message. i.e w('fnc_x dbg x=',1,'y=',2)
    
    :param str m: Text message
    :param args: Additional stringifiable parts of the message.
    """

    for a in args:
        m += ' '+str(a)
    sys.stderr.write(m+"\n")



# Filename utils
    
def enumerate_files(dir,pattern):
    """ Enumerate files in a directory that matches the pattern.
    
    :param str dir: Directory path
    :param str pattern: Pattern to match in enumeration
    :returns: Iterator that returns filenames with full path.
    """

    regex = re.compile(pattern)
    for f in os.listdir(dir):
        if regex.match(f):
            yield os.path.abspath(dir+'/'+f)
                        

def checkcreatedir(dir):
    """ Create dir if it does not exist.

    :param str dir: Dir name to create.
    """
    if not (os.path.exists(dir) and os.path.isdir(dir)):
        os.mkdir(dir)

    return dir



# Path generation functions

# Globals
_glob_result_dir=None

def module_init(result_dir):
    """ Initialize module paths etc.
    
    :param str result_dir: Set the global result directory
    """

    global _glob_result_dir
    
    _glob_result_dir=result_dir


def resultdir(day=None):
    """ Get Day object and return (existing) result directory name for the day.
    If no day is given, than return the root result dir.

    :param Day day: Day obj or None
    :returns: Path to the result directory
    """

    global _glob_result_dir
    
    if day:
        d= '%s/%s'%(_glob_result_dir, str(day))
        checkcreatedir(d)
        return d
    else:
        return _glob_result_dir


                        


# IP handling

def normalize_ipv4_prefix(pfx):
    """ Take Cisco/IANA prefix, which might be trimmed (= 192.168.1/24) or
    without mask on classful boundary (192.168.1.0) and produce
    correct prefix.

    :param str pfx: Prefix in the text form
    :returns: Normalized prefix in text form
    """

    
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

    # Main body
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
    

def unpack_ripe_file(filename):
    """ Decompress .tar.bz2 file that contains RIPE DB tree into a temp dir.
    Return temp dir name.

    :param str filename: Filename of the archive to decompress
    :returns: Reulting dir path
    """
    
    TMPDIR_PREFIX='bgpcrunch'
    
    dir=tempfile.mkdtemp(prefix=TMPDIR_PREFIX)
    c=BIN_TAR+' jxf '+filename+' -C '+dir
    d('mktempdir:', dir, '+ running:', c)
    os.system(c)
    d('Done:', c)
    return dir


def cleanup_path(path):
    """ Delete the specified subtree

    :param str path: Path to call rm -rf on
    """
    
    d('Cleaning up path '+path)
    os.system(BIN_RM+' -rf '+path)



def load_pickle(filename):
    """
    Load an object form the pickle file.

    :param str filename: What to load
    :returns: Loaded object
    """

    o=None
    d("Loading pickle file", filename)
    with open(filename, 'rb') as input:
        o = pickle.load(input)
    return o



def save_pickle(obj, outfile):
    """ Save an object to a pickle file.

    :param obj: Obj to save
    :param str outfile: File to save obj to
    :returns: The saved object
    """
    
    d("Saving pickle file", outfile)
    with open(outfile, 'wb') as output:
        pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)

    return obj


def intersect(l1, l2):
    """ Intersect two lists (this should be used for intersecting
    lists of Day objects.)

    :param l1: List 1
    :param l2: List 2
    :returns: Iterator returning the intersection
    """
    
    for i in l1:
        if i in l2:
            yield i

    
# Exported classes


class Day(object):
    """ Day representation in compact form. The
    object basically contains only the date but it can be converted
    to different formats that are being used in the file names.
    """

    def __init__(self,time_tuple=None):
        """
        :param time_tuple: (year, month, day)
        """
        if time_tuple:
            self.setTime(time_tuple)

    def setTime(self,time_tuple):
        """
        :param time_tuple: (year, month, day)
        """
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
        """
        :returns: year-month-day string
        """
        return ("%04d" % self.time[0])+'-'+("%02d" % self.time[1])+'-'+("%02d" % self.time[2])

    def __repr__(self):
        """
        :returns: year-month-day string
        """
        return self.__str__()

    def __cmp__(self,other):
        """ Compare days (older<newer)
        :param other: The other Day obj do compare
        :returns: -1, 0 or 1 (cmp)
        """
        assert isinstance(other, Day)
        return cmp(self.time, other.time)


class _IPLookupTreeNode(object):
    """ Internal Node for the IPLookupTree. Should not be
    even public unless cPickle needs it. How unfortunate... """
    def __init__(self):
        self.one=None # _IPLookupTreeNode or None
        self.zero=None # _IPLookupTreeNode or None
        self.end=None # String (do not use ipaddr.IPNetwork, pickle fails in that case)
        self.data=None # cave pickle
    
class IPLookupTree(object):
    """ Lookup tree for holding list of IP (IPv4/IPv6) prefixes. """
    def __init__(self,ipv6=False):
        """
        :param bool ipv6: IPv6 flag
        """
        self.ipv6=ipv6
        self.root=_IPLookupTreeNode()

    def _bits(self,chararray):
        """ Convert 8-bit chars to list of bools (bits)
        :param chararray: 8-bit chars
        :returns: Iterator that yields bits
        """
        for c in chararray:
            ct=ord(c)
            for i in range(7,-1,-1):
                if ct & (1 << i):
                    yield True
                else:
                    yield False

    def add(self,net,data):
        """ Add node to the tree.

        :param net: IPv4/6 prefix
        :param data: Bound data (arbitrary) object
        """
        if not (isinstance(net, ipaddr.IPv4Network) or isinstance(net, ipaddr.IPv6Network)):
            net = ipaddr.IPNetwork(net)

        bits = list(self._bits(net.packed))
        index=self.root
        for bi in range(0,net.prefixlen):
            if bits[bi]:
                if not index.one:
                    index.one = _IPLookupTreeNode()
                index = index.one
            else:
                if not index.zero:
                    index.zero = _IPLookupTreeNode()
                index = index.zero
        index.end = str(net)
        index.data = data


    def _lookupAllLevelsNode(self, ip, maxMatches=0):
        """ Internal match helper.

        :param ip: IPv4/6 to match
        :param int maxMatches: Maximum matches in the return list, i.e. stop when we \
        have #maxMatches matches and ignore more specifices. 0=Unlimited
        :returns: List of resulting match candidate objects.
        """

        if not (isinstance(ip, ipaddr.IPv4Network) or isinstance(ip, ipaddr.IPv6Network) or
                isinstance(ip, ipaddr.IPv4Address) or isinstance(ip, ipaddr.IPv6Address)):
            if str(ip).find('/') > 0:
                ip = ipaddr.IPNetwork(ip)
            else:
                ip = ipaddr.IPAddress(ip)
    
        limit=128 if self.ipv6 else 32
        if isinstance(ip, ipaddr.IPv4Network) or isinstance(ip, ipaddr.IPv6Network):
            limit=ip.prefixlen

        candidates=[]

        index = self.root
        # match address
        for (bi,b) in enumerate(self._bits(ip.packed)):
            if index.end and ip in ipaddr.IPNetwork(index.end): # match
                candidates.append(index)

            if bi >= limit or (maxMatches > 0 and len(candidates) >= maxMatches):
                # limit reached - either pfxlen or maxMatches
                return candidates

            # choose next step 1 or 0
            if b:
                index = index.one
            else:
                index = index.zero

            # dead end
            if not index: 
                return candidates

        # in case full IP address was matched in the tree
        return candidates

    def lookupAllLevels(self, ip, maxMatches=0):
        """ Lookup in the tree. Find all matches (i.e. all objects that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) Return all the results in a form of
        list. The first is the least specific match and the last is the most
        specific one.

        :param ip: IPv4/6 to match
        :param int maxMatches: Maximum matches in the return list, i.e. stop when we \
        have #maxMatches matches and ignore more specifices. 0=Unlimited
        :returns: List of resulting data in matching nodes.
        """
        return [n.data for n in self._lookupAllLevelsNode(ip, maxMatches)]

    def lookupFirst(self, ip):
        """ Lookup in the tree. Find the first match (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.)

        :param ip: IPv4/6 to match
        :returns: Resulting data in first matching node.
        """

        result = self.lookupAllLevels(ip, 1)
        if result:
            return result[0]
        else:
            return None

    
    def lookupBest(self, ip):
        """ Lookup in the tree. Find the most specific match (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) It is pretty much the same the routing
        mechanisms are doing.

        :param ip: IPv4/6 to match
        :returns: Resulting data in best matching node.
        """
        
        result = self.lookupAllLevels(ip)
        if result:
            return result[-1]
        else:
            return None

    def lookupNetExact(self, net):
        """ Lookup in the tree. Find the exact match for a net (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) It is pretty much the same the routing
        mechanisms are doing.

        :param net: IPv4/6 prefix to match
        :returns: Resulting data in exact matching node.
        """

        results = self._lookupAllLevelsNode(net)
        return [r.data for r in results if ipaddr.IPNetwork(r.end).prefixlen == ipaddr.IPNetwork(net).prefixlen]

    def dump(self):
        """ Dump the tree. """
        
        def printSubtree(node):
            """ Print subtree of the IPLookupTree.
            :param node: Root to print (recursively)
            """

            if not node:
                return
            
            if node.end:
                print str(node.end)+(' '+str(node.data) if node.data else '')
                
            printSubtree(node.zero)
            printSubtree(node.one)

        printSubtree(self.root)
        
