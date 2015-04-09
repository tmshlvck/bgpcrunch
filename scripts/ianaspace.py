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


import csv
import ipaddr
import itertools

import common

iana_ipv4_list='/home/brill/projects/bgpcrunch/data/ipv4-address-space.csv'
iana_ipv6_list='/home/brill/projects/bgpcrunch/data/ipv6-unicast-address-assignments.csv'
RIRS=['LACNIC','APNIC','ARIN','RIPE NCC','AFRINIC']



class IanaDirectory(object):
        def __init__(self,ipv6):
                self.ipv6=ipv6
                #self.table=list(self._read_iana_networks(self.ipv6))
                self.tree=common.IPLookupTree(self.ipv6)
                for n in self._read_iana_networks(self.ipv6):
                        self.tree.add(n[0],n)


        def _read_iana(self,ipv6):
                listfile=iana_ipv4_list if not ipv6 else iana_ipv6_list

                with open(listfile, 'rb') as csvfile:
                        reader = csv.reader(csvfile)
                        for row in reader:
                                yield row



        def _read_iana_networks(self,ipv6):
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


                def normalize_ipv4_prefix(pfx):
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
                


                def normalize_rir(name):
                        return name.replace('Administered by ','').strip()



                for i,r in enumerate(self._read_iana(ipv6)):
                        if i == 0:
                                continue
                        pfx=r[0]
                        if not ipv6:
                                pfx=normalize_ipv4_prefix(r[0])

                        yield (ipaddr.IPNetwork(pfx),r[5] if ipv6 else r[4],r[1] if ipv6 else normalize_rir(r[1]))

                                

                
        def resolve_network(self,net):
                """ Takes ipaddr.IPv[46]Network instance or string that can be used to construct it and
                returns (IPv4Network() or IPv6Network object, status(str), RIRID(str))
                i.e. (IPv6Network('2001:8000::/19'), 'ALLOCATED', 'APNIC') ."
                """
                
                if not (isinstance(net, ipaddr.IPv4Network) or isinstance(net, ipaddr.IPv6Network)):
                        net = ipaddr.IPNetwork(net)

                return self.tree.lookupFirst(net)
                
                #for n in self.table:
                #        if net in n[0]:
                #                return n
                #return None




def create_rir_pfx_stats(ipv6=False,bestonly=True):
        iana = ianaspace.IanaDirectory(ipv6)
        timeline=[]

        for t in common.enumerate_available_times(ipv6):
                outtxt = common.get_result_dir(t)+'rirstats'+'6' if ipv6 else '4'+'.txt'
                rirpfxlens={}
                bgpdump=cisco.parse_cisco_bgp_time(t,ipv6)
                for (i,pv) in enumerate(bgpdump):
                        if bestonly and not (pv[0] and '>' in pv[0]):
                                continue

                        r=iana.resolve_network(pv[1])
                        name=r[2]
                        if r[1] == 'LEGACY' and not name in RIRS:
                                name='LEGACY'
                        if not name in rirpfxlens:
                                rirpfxlens[name]=[]
                        rirpfxlens[name].append(r[0].prefixlen)
                        timeline.append(itertools.flatten([t,[rirpfxlens[n] for n in RIRS]]))

                common.debug("Generating output RIR stats text "+outtxt)
                with open(outtxt,'w') as f:
                        for k in RIRS:
                                f.write(str(k)+": "+str(len(rirpfxlens[k]))+"\n")

        outgraph = common.get_result_dir()+'rirstats'+'6' if ipv6 else '4'
        common.debug("Generating output RIR stats graph with prefix "+outgraph)
        gen_multilineplot(timeline,outgraph,legend=RIRS)
        


                        
def main():
        ipv6=True

        d=IanaDirectory(ipv6)
        for x in d.table:
                print str(x)

        print "Resolve test:"
        if ipv6:
                print str(d.resolve_network(ipaddr.IPNetwork('2001:1ab0::/32')))
        else:
                print str(d.resolve_network(ipaddr.IPNetwork('217.31.48.0/20')))




if __name__ == '__main__':
        main()
