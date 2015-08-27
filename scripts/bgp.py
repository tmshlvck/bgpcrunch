#!/usr/bin/python
#
# BGPcrunch - BGP analysis toolset
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
import getopt

import common
import graph
import cisco


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
    """ Return number of ASes in ASpath. """ 
    return (len(p.split(' '))-1)


def gen_buckets(bgpdump,ipv6=False,bestonly=False):
    """
    Reads Cisco show ip bgp output captured in a file and returns
    list of lists of path length where:
    r=gen_buckets(...)
    r[16]=[x,y,z,...] ; x,y,z are strings. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...

    bgpdump - data structure of parsed show ip bgp dump
    ipv6 - bool (=expect /128 masks)
    bestonly - ignore received but not used routes
    """
    
    buckets=[]
    rng=32
    if ipv6:
        rng=128

    for i in range(0,rng+1):
        buckets.append([])

    for r in bgpdump:
        if bestonly and not (r[0] and '>' in r[0]):
            continue
        
        nm = get_pfxlen(r[1])
        try:
            buckets[nm].append(get_bgp_pathlen(r[3]))
        except:
            print "EXC: nm="+str(nm)+" r[6]="+str(r)

    return buckets


def avg_pathlen(bucket):
    """ Count avgpathlen for a bucket (=list of pathlens like
    ["1 2 3","1 2","1 2 3 4",...]
    """

    if len(bucket)>0:
        return sum(bucket)/float(len(bucket))
    else:
        return 0


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

        if pc == 0:
            yield "/%d : N/A (0 prefixes)"%i
        else:
            yield "/%d : %.2f (%d prefixes)"%(i, round(avg_pathlen(b), 2), pc)

    yield "Total prefixes examined: %d"%tpfx


def gen_pathlen_textfile(buckets,outfile,ipv6):
    """ Gen textfile from buckets of one day (=list 1..32 or 128 of lists of pathlenghts).
    """

    common.d('gen_pathlen_textfile genering', outfile)
    with open(outfile,'w') as of:
        for l in format_buckets(buckets):
            of.write(l+"\n")

         
def gen_pathlen_graph(buckets,outfile,ipv6):
    """ Generate graph from buckets of each day. Graph pathlengths (one point per day). """
    
    common.d('gen_pathlen_graph genering', outfile)
    graph.gen_lineplot([((i+1),avg_pathlen(b)) for i,b in enumerate(buckets)],
                       outfile, xlabel='Prefix length', ylabel='Avg path len',
                       title='\# of hops')
    

def gen_pathlen_timegraphs(bucket_matrix, filenamepfx, ipv6=True):
    """ Generate graphs pathlen4-<number> when number is the length of the examined
    prefix. Graph contains average length of paths with the prefix length set by number.
    It also creates 3d graph pathlen4-3d with all prefix lenght in one dimension.
    And finally, it creates pathlen4-avg which graphs average for all prefix lengths. """
    
    rng=32
    if ipv6:
        rng=128

    pfxlen = []
    for i in range(0,rng+1):
        pfxlen.append([])
                        
    avg = []
    d3d = []

    if ipv6:
        filenamepfx=filenamepfx+'/pathlen6-'
    else:
        filenamepfx=filenamepfx+'/pathlen4-'

    times=sorted(bucket_matrix.keys())
    for t in times:
        ts=str(t)
        avgt=0
        nonzerocnt=0
        for i in range(0,rng+1):
            a=avg_pathlen(bucket_matrix[t][i])
            if not a==0:
                d3d.append((ts,i,a))
            pfxlen[i].append((ts,a))
            avgt+=a
            if a>0:
                nonzerocnt+=1
        if nonzerocnt > 0:
            avg.append((ts,avgt/float(nonzerocnt)))

    if avg:
        common.d("bgp.gen_pathlen_timegraph creating", filenamepfx+'avg')
        graph.gen_lineplot(avg,filenamepfx+'avg', ylabel='Total avg path len', title='\# of hops')

    for i in range(0,rng+1):
        if pfxlen[i]:
            common.d("bgp.gen_pathlen_timegraph creating", filenamepfx+str(i))
            graph.gen_lineplot(pfxlen[i],filenamepfx+str(i), ylabel='Avg path len', title='\# of hops')

    if d3d:
        graph.gen_3dplot(d3d,filenamepfx+'3d', ylabel='Prefix length', zlabel='Avg path      \nlength', title='\# of hops')



def gen_prefixcount_timegraphs(bucket_matrix, filenamepfx, ipv6=False):
    """ Generate graphs pfxcount4-<number> that shows how many prefixes
    of the length <number> was in DFZ at the defined time. It also generates
    graph pfxcount-sum that shows all the prefixes regardless of prefix length.
    """

    rng=32
    if ipv6:
        rng=128
    
    if ipv6:
        filenamepfx=filenamepfx+'/pfxcount6-'
    else:
        filenamepfx=filenamepfx+'/pfxcount4-'

    sumall=[]
    counts=[]
    for i in range(0,rng+1):
        counts.append([])
    
    times=sorted(bucket_matrix.keys())
    for t in times:
        s=0
        ts=str(t)
        for i in range(0,rng+1):
            cnt=len(bucket_matrix[t][i])
            s+=cnt
            counts[i].append((ts,cnt))
        sumall.append((ts,s))

    if sumall:
        common.d("bgp.gen_prefixcount_timegraph creating", filenamepfx+'sum')
        graph.gen_lineplot(sumall,filenamepfx+'sum', ylabel='Prefix count', title='\# of pfxes')

    for i in range(0,rng+1):
        if counts[i]:
            common.d("bgp.gen_prefixcount_timegraph creating", filenamepfx+str(i))
            graph.gen_lineplot(counts[i],filenamepfx+str(i), ylabel='/%d pfx count'%i, title='\# of pfxes')




def create_path_matrix(host, days, ipv6=False):
    """ Generate matrix: [t:buckets,...] where buckets (r) contains
    r[16]=[x,y,z,...] ; x,y,z are strings. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...
    """
    bucket_matrix={}

    for t in days:
        bgpfile=bgpdump_pickle(t, host, ipv6)
        if not bgpfile:
            common.d("bgp.create_path_matrix skipping time "+str(t)+"...")
            continue

        common.d("bgp.create_path_matrix processing time "+str(t)+"...")

        bgpdump=common.load_pickle(bgpfile)
        bucket_matrix[t]=gen_buckets(bgpdump, ipv6, bestonly=True)

    return bucket_matrix



# File handling

def bgpdump_pickle(day,host,ipv6=False,check_exist=True):
        """ Get Day object and return filename for the parsing result pickle. """
        
        fn = '%s/bgp%d-%s.pickle'%(common.resultdir(day), (6 if ipv6 else 4), host)
        if check_exist and not os.path.isfile(fn):
                return None
        else:
                return fn


def decode_bgp_filename(filename):
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


# Module interface


def module_listdays(bgp_hosts, bgp_data, ipv6=False):
    """
    Enumerate days that the module can analyze.

    bgp_hosts: list of hostnames
    bgp_data: hash bgp_host -> source directory
    ipv6: flag

    Returns generator of list of tuples (Day,filename).
    """

    for host in bgp_hosts:
        for fn in common.enumerate_files(bgp_data[host], "bgp-%s-[0-9-]+\.txt.bz2"%
                                         ("ipv6" if ipv6 else "ipv4")):
            yield (common.Day(decode_bgp_filename(fn)[1:4]), fn)


def module_preprocess(bgp_hosts, bgp_data, ipv6=False):
        """
        Runs Cisco parser and parse files from data like
        data/marge/bgp-ipv4-2014-04-01-01-17-01.txt.bz2
        and creates
        results/2014-04-01/bgp4-marge.pickle
        Returns list of Time objects.

        bgp_hosts: list of hostnames
        bgp_data: hash bgp_host -> source directory
        """

        out_days = []

        for host in bgp_hosts:
            for t,fn in module_listdays(bgp_hosts, bgp_data, ipv6):
                common.d('BGP in:', fn, 'time:', t)
                outdir = common.resultdir(t)
                outfile = bgpdump_pickle(t, host, ipv6, False)

                if os.path.isfile(outfile):
                    common.d('BGP out:', outfile, 'exists. Skip.')
                else:
                    common.d('BGP out:', outfile)
                    cisco.gen_bgpdump_pickle(fn, outfile, ipv6)




def module_postprocess(host, days, ipv6=False):
    """ Main function to be called from run_all. Returns nothing but generates a lot of result files. """
    m=create_path_matrix(host, days, ipv6)
    gen_pathlen_timegraphs(m, common.resultdir(), ipv6)
    gen_prefixcount_timegraphs(m, common.resultdir(), ipv6)

    for d in days:
        resultdir=common.resultdir(d)
        outfile='%s/%s-pathlen%d.txt'%(resultdir, host, (6 if ipv6 else 4))
        gen_pathlen_textfile(m[d], outfile, ipv6)
        outfilepfx='%s/%s-pathlen%d'%(resultdir, host, (6 if ipv6 else 4))
        gen_pathlen_graph(m[d], outfilepfx, ipv6)
        


# Testing and command-line interface

def main():
    def usage():
        print """bgp.py [-6] [-f filename] -- generate matrix from a captured
Cisco show ip bgp or show ipv6 bgp
  -6 : expect show ipv6 bgp instead of show ip bgp capture
  -f filename : analyze filename instead of stdin
  -b : consider only best routes
"""
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h6bf:')
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(2)
    
    ipv6=False
    filename=None
    bestonly=False
    
    for o,a in opts:
        if o == '-6':
            ipv6=True
        elif o == '-f':
            filename = a
        elif o == '-b':
            bestonly=True
        elif o == 'h':
            usage()
            sys.exit(0)
        else:
            usage()
            sys.exit(2)


    bgpdump = cisco.parse_cisco_bgp_file(filename)
    b=gen_buckets(bgpdump,ipv6,bestonly)
    for l in format_buckets(b):
        print l


if __name__ == "__main__":
    main()
