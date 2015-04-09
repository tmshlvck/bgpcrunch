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
import ianaspace






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

import gc
def main():
#        bgp.create_bgp_stats(ipv6=False)
#        bgp.create_bgp_stats(ipv6=True)

        ianaspace.create_rir_pfx_stats(ipv6=False)


#        rdb=create_ripe_objectdb_stats()


if __name__ == '__main__':
    main()
