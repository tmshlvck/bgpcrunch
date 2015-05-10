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


import os
import re

import common

import bgp
import cisco
import ianaspace
import rpsl


ROOT_DIR=os.path.abspath(os.path.dirname(os.path.realpath(__file__))+'/..')
DATA_DIR=ROOT_DIR+'/data'
RESULT_DIR=ROOT_DIR+'/results'
BGP_DATA={'marge':DATA_DIR+'/marge',}
BGP_HOSTS=['marge']
IANA_IPV4=DATA_DIR+'/ipv4-address-space.csv'
IANA_IPV6=DATA_DIR+'/ipv6-unicast-address-assignments.csv'

RIPE_DATA=DATA_DIR+'/ripe'



# Module data crunching routies

def iana_module_prepare(ipv6=False):
        """ Initialize ianaspace's IanaDirectory object for the current AF. """

        fn = (IANA_IPV6 if ipv6 else IANA_IPV4)
        return ianaspace.IanaDirectory(fn,ipv6)



def main():
        common.module_init(RESULT_DIR)

        # Prepare RPSL parsing products
        ripe_days = sorted(rpsl.module_prepare(DATA_DIR))

        for ipv6 in [False,True]:
                # Prepare IANA directory
                ianadir=iana_module_prepare(ipv6)

                # Create BGP data in result directories (= ROOT/results/2014-04-01/bgp4-marge.pickle).
                # Use filename_bgp_pickle_for_day() to get the filename.

                bgp_days = sorted(bgp.module_prepare(BGP_HOSTS, BGP_DATA, ipv6))

                for host in BGP_HOSTS:
                        # Run basic BGP stats
                        bgp.module_run(host, bgp_days, ipv6)

                        # Run basic BGP stats with regards to IANA top-level assignments
                        ianaspace.module_run(ianadir, host, bgp_days, ipv6, bestonly=True)

                rpsl.module_run(ripe_days, ianadir, host, bgp_days, ipv6)


if __name__ == '__main__':
    main()
