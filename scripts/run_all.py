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
import bgp
import cisco



def create_path_matrix(ipv6=False):
        bucket_matrix={}

        for t in common.enumerate_available_times(ipv6):
                bgpfile=common.get_bgp_file(t,ipv6)

                if not bgpfile:
                        common.debug("Skipping BGP parse for time "+str(t)+". No BGP snapshot available.")
                        continue

                resultdir=common.get_result_dir(t)
                outfile=resultdir+'/bgpdump'+('6' if ipv6 else '4')+'.pkl'

                common.debug("Processing time "+str(t)+"...")
                common.debug("BGP file: "+str(bgpfile))
                common.debug("Result dir: "+str(resultdir))
                common.debug("Output file: "+str(outfile))

                bgpdump=cisco.parse_cisco_bgp(bgpfile,outfile)
                bucket_matrix[t]=bgp.gen_buckets(bgpdump,ipv6,bestonly=True)
                
                outfile=resultdir+'/pathlen'+('6' if ipv6 else '4')+'.txt'
                bgp.generate_pathlen_text(bucket_matrix[t],outfile,ipv6)
                outfilepfx=resultdir+'/pathlen'+('6' if ipv6 else '4')
                bgp.generate_pathlen_graph(bucket_matrix[t],outfilepfx,ipv6)

        return bucket_matrix


def create_ripe_objectdb_stats():
        for t in list(set(common.enumerate_available_times(False)) |
                      set(common.enumerate_available_times(True))):
                ripefile = common.get_ripe_file(t)
                if not ripefile:
                        common.debug("Skipping RPSL parse for time "+str(t)+". No DB snapshot available.")
                        continue
                
                common.debug("Processing time "+str(t)+"...")
                common.debug("RIPE file: "+str(ripefile))

                outdir=common.unpack_ripe_file(ripefile)
                common.debug("RIPE unpack result: "+outdir)
#                common.cleanup_path(outdir)


def main():
#        m4=create_path_matrix(ipv6=False)
#        bgp.gen_pathlen_timegraphs(m4,ipv6=False)
#        bgp.gen_prefixcount_timegraph(m4,ipv6=False)
        
#        m6=create_path_matrix(ipv6=True)
#        bgp.gen_pathlen_timegraphs(m6,ipv6=True)
#        bgp.gen_prefixcount_timegraph(m6,ipv6=True)


        rdb=create_ripe_objectdb_stats()


if __name__ == '__main__':
    main()
