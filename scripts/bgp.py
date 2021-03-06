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

    :param str pfx: IP address as string.
    :returns: (Int) Netmask.
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
    """ Return number of ASes in AS-path.

    :param str p: AS-path to parse
    :returns: Integer = number of ASes in AS-path
    """ 
    return (len(p.split(' '))-1)


def gen_buckets(bgpdump,ipv6=False,bestonly=False):
    """
    Reads Cisco show ip bgp output captured in a file and returns
    list of lists of path length where:
    r=gen_buckets(...)
    r[16]=[x,y,z,...] ; x,y,z are ints. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...

    :param bgpdump: Data structure of parsed show ip bgp dump
    :param bool ipv6: (=expect /128 masks)
    :param bool bestonly: Ignore received but not used routes
    :returns: List representing the buckets
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

    :param bucket: The list representing the bucket
    :returns: Integer representing the avg path length
    """

    if len(bucket)>0:
        return sum(bucket)/float(len(bucket))
    else:
        return 0


def format_buckets(buckets):
    """ Generate textual representation of buckets.
    
    :param buckets: List of integers representing the buckets.
    :returns: List of lines = the text representation.
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

    :param buckets: List representing the buckets
    :param str outfile: File name to write
    :param bool ipv6: IPv6 flag
    """

    common.d('gen_pathlen_textfile genering', outfile)
    with open(outfile,'w') as of:
        for l in format_buckets(buckets):
            of.write(l+"\n")

         
def gen_pathlen_graph(buckets,outfile,ipv6):
    """ Generate graph from buckets of each day. Graph pathlengths (one point per day).

    :param buckets: List representing the buckets
    :param str outfile: File name to write
    :param bool ipv6: IPv6 flag
    """
    
    common.d('gen_pathlen_graph genering', outfile)
    graph.gen_lineplot([((i+1),avg_pathlen(b)) for i,b in enumerate(buckets)],
                       outfile, xlabel='Prefix length', ylabel='Avg path len',
                       title='\# of hops')
    

def gen_pathlen_timegraphs(bucket_matrix, filenamepfx, ipv6=True):
    """ Generate graphs pathlen4-<number> when number is the length of the examined
    prefix. Graph contains average length of paths with the prefix length set by number.
    It also creates 3d graph pathlen4-3d with all prefix lenght in one dimension.
    And finally, it creates pathlen4-avg which graphs average for all prefix lengths.

    :param bucket_matrix: Matrix representing the buckets
    :param str filenamepfx: File name prefix to create files and write them
    :param bool ipv6: IPv6 flag
    """
    
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
        graph.gen_3dplot(d3d,filenamepfx+'3d', ylabel='Prefix length', zlabel=r'Avg path      \nlength', title='\# of hops')



def gen_prefixcount_timegraphs(bucket_matrix, filenamepfx, ipv6=False):
    """ Generate graphs pfxcount4-<number> that shows how many prefixes
    of the length <number> was in DFZ at the defined time. It also generates
    graph pfxcount-sum that shows all the prefixes regardless of prefix length.

    :param bucket_matrix: Matrix representing the buckets
    :param str filenamepfx: File name prefix to create files and write them
    :param bool ipv6: IPv6 flag
    """

    rng=32
    if ipv6:
        rng=128
    
    if ipv6:
        filenamepfx=filenamepfx+'/pfxcount6-'
    else:
        filenamepfx=filenamepfx+'/pfxcount4-'

    sumall=[]
    avgpfxlen=[]
    counts=[]
    for i in range(0,rng+1):
        counts.append([])
    
    times=sorted(bucket_matrix.keys())
    for t in times:
        s=0
        apl=0
        ts=str(t)
        for i in range(0,rng+1):
            cnt=len(bucket_matrix[t][i])
            s+=cnt
            apl+=cnt*i
            counts[i].append((ts,cnt))
        sumall.append((ts,s))
        avgpfxlen.append((ts,(float(apl)/s)))

    if sumall:
        common.d("bgp.gen_prefixcount_timegraph creating", filenamepfx+'sum')
        graph.gen_lineplot(sumall,filenamepfx+'sum', ylabel='Prefix count', title='\# of pfxes')

    if avgpfxlen:
        common.d("bgp.gen_prefixcount_timegraph creating", filenamepfx+'avgpfxlen')
        graph.gen_lineplot(avgpfxlen,filenamepfx+'avgpfxlen', ylabel='avg pfx length', title='BGP average')

    for i in range(0,rng+1):
        if counts[i]:
            common.d("bgp.gen_prefixcount_timegraph creating", filenamepfx+str(i))
            graph.gen_lineplot(counts[i],filenamepfx+str(i), ylabel='/%d pfx count'%i, title='\# of pfxes')




def create_path_matrix(host, days, ipv6=False):
    """ Generate matrix: [t:buckets,...] where buckets (r) contains
    r[16]=[x,y,z,...] ; x,y,z are ints. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...

    :param str host: Host name to analyze
    :param days: List of Day obj. to analyze
    :param bool ipv6: IPv6 flag
    :returns: Bucket matrix
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
        """ Get Day object and return filename for the parsing result pickle.

        :param Day day: Day to find
        :param bool ipv6: IPv6 flag
        :param bool check_exist: if True check existence of the picke file and \
        return None when the file does not exist. If false return the filename \
        anyway.
        :returns: Filename of the corresponding file
        """
        
        fn = '%s/bgp%d-%s.pickle'%(common.resultdir(day), (6 if ipv6 else 4), host)
        if check_exist and not os.path.isfile(fn):
                return None
        else:
                return fn


def decode_bgp_filename(filename):
    """ Decode BGP filename to tuple.

    :param filename: string, i.e. 'bgp-ipv6-2014-2-16-1-17-2.txt.bz2'
    :returns: tuple (ipv6,year,month,day,hour,min,sec)
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
    """ Enumerate days that the module can analyze.

    :param bgp_hosts: list of hostnames
    :param bgp_data: hash bgp_host -> source directory
    :param bool ipv6: IPv6 flag

    :returns: Generator of list of tuples (Day,filename).
    """

    for host in bgp_hosts:
        for fn in common.enumerate_files(bgp_data[host], "bgp-%s-[0-9-]+\.txt.bz2"%
                                         ("ipv6" if ipv6 else "ipv4")):
            yield (common.Day(decode_bgp_filename(fn)[1:4]), fn)


def module_preprocess(bgp_hosts, bgp_data, ipv6=False):
        """ Runs Cisco parser and parse files from data like
        data/marge/bgp-ipv4-2014-04-01-01-17-01.txt.bz2
        and creates
        results/2014-04-01/bgp4-marge.pickle
        Returns list of Time objects.

        :param bgp_hosts: list of hostnames
        :param bgp_data: hash bgp_host -> source directory
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
    """ Main function to be called from run_all.
    Returns nothing but generates a lot of result files.

    :param hosts: list of hostnames
    :param days: list of days
    :param bool ipv6: IPv6 flag
    """
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
    """ Run self-test. Do not use.
    """
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
