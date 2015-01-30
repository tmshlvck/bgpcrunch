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



import common




  
import parse_paths
def generate_histogram(infile,outfile,ipv6):
        b=parse_paths.get_buckets_from_file(infile,ipv6,True)
        
        with open(outfile,'w') as of:
                for l in parse_paths.format_buckets(b):
                        of.write(l+"\n")

        return b


def create_histograms():
        def avg_pathlen(bucket):
                if len(bucket)>0:
                        return sum(bucket)/float(len(bucket))
                else:
                        return 0

        def gengraphs(buckets,ipv6=True):
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
                        filenamepfx=filenamepfx+'/histogram6-'
                else:
                        filenamepfx=filenamepfx+'/histogram4-'

                times=sorted(buckets.keys())
                for t in times:
                        ts=common.time_to_str(t)
                        avgt=0
                        nonzerocnt=0
                        for i in range(0,rng+1):
                                a=avg_pathlen(buckets[t][i])
                                d3d.append((ts,i,a))
                                pfxlen[i].append((ts,a))
                                avgt+=a
                                if a>0:
                                        nonzerocnt+=1
                        if nonzerocnt > 0:
                                avg.append((ts,avgt/float(nonzerocnt)))

                common.gen_lineplot(avg,filenamepfx+'avg')

                for i in range(0,rng+1):
                        common.gen_lineplot(pfxlen[i],filenamepfx+str(i))

                common.gen_3dplot(d3d,filenamepfx+'3d')



        buckets4={}
        buckets6={}

        # IPv4
        for t in common.enumerate_available_times(False):
                bgpfile=common.get_bgp_file(t,False)
                resultdir=common.get_result_dir(t)

                print "IPv4 Processing time "+str(t)+"..."
                print "BGP file: "+str(bgpfile)
                print "Result dir: "+str(resultdir)

                buckets4[t]=generate_histogram(bgpfile,resultdir+'/histogram4.txt',False)
        gengraphs(buckets4,False)

        # IPv6
        for t in common.enumerate_available_times(True):
                bgpfile=common.get_bgp_file(t,True)
                resultdir=common.get_result_dir(t)

                print "IPv6 Processing time "+str(t)+"..."
                print "BGP file: "+str(bgpfile)
                print "Result dir: "+str(resultdir)

                buckets6[t]=generate_histogram(bgpfile,resultdir+'/histogram6.txt',True)
        gengraphs(buckets6,True)


def main():
        create_histograms()
        
#                print get_ripe_file(t)




if __name__ == '__main__':
    main()
