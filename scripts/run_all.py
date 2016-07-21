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
        and do intersection.

        :returns: List of available days
        """
        bgp4 = [d for d,fn in bgp.module_listdays(BGP_HOSTS, BGP_DATA, False)]
        bgp6 = [d for d,fn in bgp.module_listdays(BGP_HOSTS, BGP_DATA, True)]
        ripe = [d for d,fn in rpsl.module_listdays(DATA_DIR)]

        days = common.intersect(bgp4, bgp6)
        days = common.intersect(days, ripe)
        return sorted(list(days))

def preprocess_data(threads=1):
        """
        Preprocess data. Meaning: Read textual data and create proper Python datastructures
        and save them in form of pickles. This should not be much time consuming and it has
        to be done on the one place (at least the code counts on in to some extent).

        :param int threads: Number of threads to run
        """
        
        # Prepare RPSL parsing products
        rpsl.module_preprocess(DATA_DIR, threads)

        for ipv6 in [False,True]:
                # Create BGP data in result directories (= ROOT/results/2014-04-01/bgp4-marge.pickle).
                # Use filename_bgp_pickle_for_day() to get the filename.
                bgp.module_preprocess(BGP_HOSTS, BGP_DATA, ipv6)



def process_workpackage(days, threads=1):
        """
        This function contains the most time consuming work that has to be done for
        each day but it does not aggregate days. Meaning: Days can be processed concurently.
        One level of concurency is achieved inside modules using multiprocessing (tuned for each
        module. Another is achieved by splitting workpackages and distributing them over
        different servers.

        :param days: Days that forms the workpackage
        :param int threads: Threads to run
        """

        for ipv6 in [False,True]:
                # Initialize ianaspace's IanaDirectory object for the current AF.
                ifn = (IANA_IPV6 if ipv6 else IANA_IPV4)
                ianadir=ianaspace.IanaDirectory(ifn,ipv6)

                for host in BGP_HOSTS:
                        # Run RPSL matching (routes and paths)
                        rpsl.module_process(days, ianadir, host, ipv6, threads)



def postprocess_workpackage(days):
        """ Generate graphs and text outputs. This should not be that much time-consuming
        and it is needs to run on one place and in single thread. Sorry...

        :param days: Days that form the workpackage
        """

        for ipv6 in [False,True]:
                ifn = (IANA_IPV6 if ipv6 else IANA_IPV4)
                ianadir=ianaspace.IanaDirectory(ifn,ipv6)
                
                for host in BGP_HOSTS:
                        # Run basic BGP stats
                        bgp.module_postprocess(host, days, ipv6)

                        # Run basic BGP stats with regards to IANA top-level assignments
                        ianaspace.module_process(ianadir, host, days, ipv6, bestonly=True)

                        # Generate advanced RPSL matching stats
                        rpsl.module_postprocess(days, ianadir, host, ipv6)




# Command line helper functions
DAY_MATCH=re.compile("^([0-9]+)-([0-9]+)-([0-9]+)$")

def decode_day(text):
        """ Decode day code 2015-05-01 and create Day object

        :param str text: Text representation of the day
        :returns: The commond.Day object representing the text
        """
        m=DAY_MATCH.match(text)
        if m:
                return common.Day((int(m.group(1)), int(m.group(2)), int(m.group(3))))

def read_days(filename):
        """ Helper for command line.
        This function reads a file that contains string representation
        of Day objects each on one line and creates a list of corresponding
        objects.

        :param str filename: Filename to read
        :returns: Iterator that yields common.Day objects
        """

        with open(filename, 'r') as f:
                for l in f.readlines():
                        d=decode_day(l)
                        if d:
                                yield d



def main():
        """ run_all.py entrypoint. Everything starts here! """

        parser = argparse.ArgumentParser(description='Run BGPCRUNCH suite.')
        parser.add_argument('--preprocess', dest='preproc', action='store_true',
                            help='run only module preprocess routines')
        parser.add_argument('--wp', dest='wpd', action='store', help='file with workpackage specs')
        parser.add_argument('--days', dest='day', action='store', nargs="*", help='command line workpackage specs')
        parser.add_argument('--postprocess', dest='postproc', action='store_true',
                            help='run only module postprocess routines')
        parser.add_argument('--process', dest='proc', action='store_true',
                            help='run only module process routines')
        parser.add_argument('--listdays', dest='listdays', action='store_true',
                            help='list only available days and end')
        parser.add_argument('--threads', dest='thr', type=int, action='store', help='run THR threads', default=1)
        args = parser.parse_args()
        doall = (True if not args.preproc and not args.proc and not args.postproc else False)

        # Prepare run
        common.module_init(RESULT_DIR)

        # Decide days to run in workpackage
        days = None
        if args.wpd:
                days=list(read_days(args.wpd))
        elif args.day:
                days=[decode_day(d) for d in args.day]
        else:
                days=get_available_days()

        # Run preprocess, process and postprocess
        if args.listdays:
                for d in days:
                        print str(d)
                return

        if doall or args.preproc:
                preprocess_data(args.thr)
                if args.preproc:
                        return

        if doall or args.proc:
                process_workpackage(days, args.thr)
                if args.proc:
                        return

        if doall or args.postproc:
                postprocess_workpackage(days)



if __name__ == '__main__':
    main()
