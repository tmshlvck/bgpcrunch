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


import csv
import ipaddr

import common
import graph
import cisco
import bgp

# Constants

RIRS=['LACNIC','APNIC','ARIN','RIPE NCC','AFRINIC']

# Exported classes

class IanaDirectory(object):
        """ IANA directory object representation """
        
        def __init__(self,listfile,ipv6):
                """ Create the IANA directory from csv file.

                :param str listfile: File to read
                :param bool ipv6: IPv6 flag
                """
                
                self.ipv6=ipv6
                self.listfile=listfile
                #self.table=list(self._read_iana_networks(self.ipv6))
                self.tree=common.IPLookupTree(self.ipv6)
                for n in self._read_iana_networks(self.ipv6):
                        self.tree.add(n[0],n)


        def _read_iana(self,ipv6):
                """ Internal method. Do not use.
                Read IANA csv file and return rows.

                :param bool ipv6: IPv6 flag
                :returns: Iterator that generates rows = tuples of strings.
                """
                
                with open(self.listfile, 'rb') as csvfile:
                        reader = csv.reader(csvfile)
                        for row in reader:
                                yield row



        def _read_iana_networks(self,ipv6):
                """ Internal method. Do not use.
                Read IANA csv file and return parsed rows.

                :param bool ipv6: IPv6 flag
                :returns: Iterator that generates rows = tuples \
                (ipaddr.IPNetwork, status, RIR ID), status might be ALLOCATED,\
                LEGACY or RESERVED
                """

                def normalize_rir(name):
                        return name.replace('Administered by ','').strip()

                for i,r in enumerate(self._read_iana(ipv6)):
                        if i == 0:
                                continue
                        pfx=(r[0] if ipv6 else common.normalize_ipv4_prefix(r[0]))

                        yield (ipaddr.IPNetwork(pfx),r[5] if ipv6 else r[4],r[1] if ipv6 else normalize_rir(r[1]))

                                

                
        def resolve_network(self,net):
                """ Resolve  ipaddr.IPv[46]Network to the IANA tuple.

                :param net: ipaddr.IPv[46]Network instance or string that can be used to\
                construct it
                :returns: (IPv4Network() or IPv6Network object, status(str), RIRID(str)) \
                i.e. (IPv6Network('2001:8000::/19'), 'ALLOCATED', 'APNIC') .
                """
                
                if not (isinstance(net, ipaddr.IPv4Network) or isinstance(net, ipaddr.IPv6Network)):
                        net = ipaddr.IPNetwork(net)

                return self.tree.lookupFirst(net)
                
                #for n in self.table:
                #        if net in n[0]:
                #                return n
                #return None


# Module interface

def module_process(ianadir, host, days, ipv6=False, bestonly=False):
        """
        Match BGP prefixes in IANA's directory and generate text
        outputs and stats that determine average active prefix counts
        and average de-aggregation for each RIR.

        :param IanaDirectory ianadir: IanaDirectory instance to match agains
        :param str host: Host to take BGP feeds from
        :param days: List of days to analyze
        :param bool ipv6: IPv6 flag
        :param bool bestonly: Take only best BGP paths into account
        """

        timeline=[]
        timelineavg=[]

        for t in days:
                rirpfxlens={}
                ifn = bgp.bgpdump_pickle(t, host, ipv6)
                if not ifn:
                        continue
                bgpdump=common.load_pickle(ifn)
                common.d("ianaspace.module_run: matching prefixes in a tree (%d)"%len(bgpdump))

                for pv in bgpdump:
                        if bestonly and not (pv[0] and '>' in pv[0]):
                                continue

                        net = ipaddr.IPNetwork(pv[1])
                        r=ianadir.resolve_network(net)
                        if not r:
                                common.w("No IANA assignment for", str(pv[1]))
                                continue
                        name=r[2]
                        if r[1] == 'LEGACY' and not name in RIRS:
                                name='LEGACY'
                        if not name in rirpfxlens:
                                rirpfxlens[name]=[]
                        rirpfxlens[name].append(net.prefixlen)
                timeline.append([str(t)]+[len(rirpfxlens[n]) for n in RIRS])
                timelineavg.append([str(t)]+[(reduce(lambda x, y: x + y, rirpfxlens[n])/
                                             float(len(rirpfxlens[n]))) for n in RIRS])

                outtxt = '%s/rirstats%d-%s.txt'%(common.resultdir(t), (6 if ipv6 else 4), host)
                common.d("Generating output RIR stats text "+outtxt)
                with open(outtxt,'w') as f:
                        for i,k in enumerate(RIRS):
                                f.write('%s: %d (avg pfxlen: %.2f)\n'%(str(k), timeline[-1][1+i],
                                                                       round(timelineavg[-1][1+i], 2)))

        if timeline:
                outgraph = '%s/rirpfxcount%d-%s'%(common.resultdir(), (6 if ipv6 else 4), host)
                common.d("Generating output RIR pfxcount graph with prefix "+outgraph)
                graph.gen_multilineplot(timeline, outgraph, legend=RIRS, ylabel='Pfx count')

        if timelineavg:
                outgraph = '%s/rirpfxlen%d-%s'%(common.resultdir(), (6 if ipv6 else 4), host)
                common.d("Generating output RIR pfxlen graph with prefix "+outgraph)
                graph.gen_multilineplot(timelineavg, outgraph, legend=RIRS, ylabel='Avg pfx len')



# Module test interface

def main():
        """ Unit testing entry point. Do not use. """

        import sys

        if len(sys.argv) != 3:
                print "usage: ianaspace <ipv6: True or False> <iana.csv>"
                return 
        ipv6=sys.argv[1].lower() in ("yes", "true", "t", "1")
        sourcefile=sys.argv[2]

        d=IanaDirectory(sourcefile, ipv6)
#        for x in d.table:
#                print str(x)

        print "Resolve test:"
        if ipv6:
                print str(d.resolve_network(ipaddr.IPNetwork('2001:1ab0::/32')))
        else:
                print str(d.resolve_network(ipaddr.IPNetwork('217.31.48.0/20')))




if __name__ == '__main__':
        main()
