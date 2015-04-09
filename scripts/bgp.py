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
import getopt

import common
import cisco


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
        
        nm = common.get_pfxlen(r[1])
        try:
            buckets[nm].append(common.get_bgp_pathlen(r[3]))
        except:
            print "EXC: nm="+str(nm)+" r[6]="+str(r)

    return buckets


def avg_pathlen(bucket):
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
            yield "/"+str(i)+" : N/A (0 prefixes)"
        else:
            yield "/"+str(i)+" : "+str(avg_pathlen(b))+" ("+str(pc)+" prefixes)"

    yield "Total prefixes examined: "+str(tpfx)



#############################

def generate_pathlen_text(buckets,outfile,ipv6):
    with open(outfile,'w') as of:
        for l in format_buckets(buckets):
            of.write(l+"\n")

         
def generate_pathlen_graph(buckets,outfile,ipv6):
    common.gen_lineplot([((i+1),avg_pathlen(b)) for i,b in enumerate(buckets)],outfile)
    

def gen_pathlen_timegraphs(bucket_matrix,ipv6=True):
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

    filenamepfx=common.get_result_dir()
    if ipv6:
        filenamepfx=filenamepfx+'/pathlen6-'
    else:
        filenamepfx=filenamepfx+'/pathlen4-'

    times=sorted(bucket_matrix.keys())
    for t in times:
        ts=common.time_to_str(t)
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
        common.gen_lineplot(avg,filenamepfx+'avg')

    for i in range(0,rng+1):
        if pfxlen[i]:
            common.gen_lineplot(pfxlen[i],filenamepfx+str(i))

    if d3d:
        common.gen_3dplot(d3d,filenamepfx+'3d')



def gen_prefixcount_timegraph(bucket_matrix,ipv6=False):
    """ Generate graphs pfxcount4-<number> that shows how many prefixes
    of the length <number> was in DFZ at the defined time. It also generates
    graph pfxcount-sum that shows all the prefixes regardless of prefix length.
    """

    rng=32
    if ipv6:
        rng=128
    
    filenamepfx=common.get_result_dir()
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
        ts=common.time_to_str(t)
        for i in range(0,rng+1):
            cnt=len(bucket_matrix[t][i])
            s+=cnt
            counts[i].append((ts,cnt))
        sumall.append((ts,s))

    if sumall:
        common.gen_lineplot(sumall,filenamepfx+'sum')

    for i in range(0,rng+1):
        if counts[i]:
            common.gen_lineplot(counts[i],filenamepfx+str(i))




def create_path_matrix(ipv6=False):
    """ Generate matrix: [t:buckets,...] where buckets (r) contains
    r[16]=[x,y,z,...] ; x,y,z are strings. It means that there was
    prefixes with netmask /16. One with AS-path length x, another y, ...
    """
    bucket_matrix={}

    for t in common.enumerate_available_times(ipv6):
        if not bgpfile:
            common.debug("Skipping BGP parse for time "+str(t)+". No BGP snapshot available.")
            continue

        common.debug("Processing time "+str(t)+"...")
        common.debug("BGP file: "+str(bgpfile))

        bgpdump=cisco.parse_cisco_bgp_time(t,ipv6)
        bucket_matrix[t]=bgp.gen_buckets(bgpdump,ipv6,bestonly=True)

    return bucket_matrix



def create_bgp_stats(ipv6=False):
    """ Main function to be called from run_all. Returns nothing but generates a lot of result files. """
    m=create_path_matrix(ipv6)
    gen_pathlen_timegraphs(m,ipv6)
    gen_prefixcount_timegraph(m,ipv6)

    resultdir=common.get_result_dir(t)
    for t in common.enumerate_available_times(ipv6):
        outfile=resultdir+'/pathlen'+('6' if ipv6 else '4')+'.txt'
        generate_pathlen_text(m[t],outfile,ipv6)
        outfilepfx=resultdir+'/pathlen'+('6' if ipv6 else '4')
        generate_pathlen_graph(m[t],outfilepfx,ipv6)
        

            

#################################





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
