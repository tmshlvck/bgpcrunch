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


import os
import re
import argparse

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



# Data processing packages

def get_available_days():
        """ List days we have all needed data for. Ask modules for that
        and do intersection. """
        bgp4 = [d for d,fn in bgp.module_listdays(BGP_HOSTS, BGP_DATA, False)]
        bgp6 = [d for d,fn in bgp.module_listdays(BGP_HOSTS, BGP_DATA, True)]
        ripe = [d for d,fn in rpsl.module_listdays(DATA_DIR)]
        
        days = common.intersect(bgp4, bgp6)
        days = common.intersect(days, ripe)
        return sorted(days)

def preprocess_data():
        """
        Preprocess data. Meaning: Read textual data and create proper Python datastructures
        and save them in form of pickles. This should not be much time consuming and it has
        to be done on the one place (at least the code counts on in to some extent).
        """
        
        # Prepare RPSL parsing products
        rpsl.module_preprocess(DATA_DIR)

        for ipv6 in [False,True]:
                # Create BGP data in result directories (= ROOT/results/2014-04-01/bgp4-marge.pickle).
                # Use filename_bgp_pickle_for_day() to get the filename.
                bgp.module_preprocess(BGP_HOSTS, BGP_DATA, ipv6)



def process_workpackage(days):
        """
        This function contains the most time consuming work that has to be done for
        each day but it does not aggregate days. Meaning: Days can be processed concurently.
        One level of concurency is achieved inside modules using threading (tuned for each
        module. Another is achieved by splitting workpackages and distributing them over
        different servers.
        """

        for ipv6 in [False,True]:
                # Initialize ianaspace's IanaDirectory object for the current AF.
                ifn = (IANA_IPV6 if ipv6 else IANA_IPV4)
                ianadir=ianaspace.IanaDirectory(ifn,ipv6)

                for host in BGP_HOSTS:
                        # Run RPSL matching (routes and paths)
                        rpsl.module_process(days, ianadir, host, ipv6)



def postprocess_workpackage(days):
        """ Generate graphs and text outputs. This should not be that much time-consuming
        and it is needs to run on one place and in single thread. Sorry... """

        for ipv6 in [False,True]:
                ifn = (IANA_IPV6 if ipv6 else IANA_IPV4)
                ianadir=ianaspace.IanaDirectory(ifn,ipv6)
                
                for host in BGP_HOSTS:
                        # Run basic BGP stats
                        bgp.module_postprocess(host, days, ipv6)

                        # Run basic BGP stats with regards to IANA top-level assignments
                        ianaspace.module_run(ianadir, host, days, ipv6, bestonly=True)

                        # Generate advanced RPSL matching stats
                        rpsl.module_postprocess(days, ianadir, host, ipv6)




# Command line helper functions
def read_days(filename):
        """ Helper for command line.
        This function reads a file that contains string representation
        of Day objects each on one line and creates a list of corresponding
        objects.
        """

        DAY_MATCH=re.compile("^([0-9])+-([0-9])+-([0-9]+)$")

        with open(filename, 'r') as f:
                for l in f.readlines():
                        m=DAY_MATCH.match(l)
                        if m:
                                yield common.Day((int(m.group(1)), int(m.group(2)), int(m.group(3))))



def main():
        """ run_all.py entrypoint. Everything starts here! """

        parser = argparse.ArgumentParser(description='Run BGPCRUNCH suite.')
        parser.add_argument('--preprocess', dest='preproc', action='store_const',
                            const=True, default=False, help='run only module preprocess routines')
        parser.add_argument('--wp', dest='wpd', action='store', help='run only module main routines')
        parser.add_argument('--postprocess', dest='postproc', action='store_const', const=True,
                            default=False, help='run only module postprocess routines')
        parser.add_argument('--listdays', dest='listdays', action='store_const', const=True,
                            default=False, help='list only available days and end')
        args = parser.parse_args()
        doall = (True if not args.preproc and not args.wpd and not args.postproc else False)

        # Prepare run
        common.module_init(RESULT_DIR)

        days = get_available_days()

        if args.listdays:
                for d in days:
                        print str(d)
                return

        if doall or args.preproc:
                preprocess_data()

        if doall or args.wpd:
                if args.wpd:
                        days=read_days(args.wpd)

                process_workpackage(days)

                if args.wpd:
                        return

        if doall or args.postproc:
                postprocess_workpackage(days)



if __name__ == '__main__':
    main()
