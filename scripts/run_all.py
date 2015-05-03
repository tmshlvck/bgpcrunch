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

#import bgp
#import cisco
#import ianaspace
#import rpsl


ROOT_DIR=os.path.abspath(os.path.dirname(os.path.realpath(__file__))+'/..')
DATA_DIR=ROOT_DIR+'/data'
RESULT_DIR=ROOT_DIR+'/results'
BGP_DATA={'marge':DATA_DIR+'/marge',}
BGP_HOSTS=['marge']
RIPE_DATA=DATA_DIR+'/ripe'
TMPDIR_PREFIX='bgpcrunch'


def resultdir_for_day(day=None):
        """ Get Day object and return (existing) result directory name for the day.
        If no day is given, than return the root result dir.
        """

        if day:
                d= '%s/%s'%(RESULT_DIR,str(day))
                common.checkcreatedir(d)
                return d
        else:
                return RESULT_DIR


def bgp_pickle_for_day(day,host,ipv6=False):
        """ Get Day object and return filename for the parsing result pickle. """
        return '%s/bgp%d-%s.pickle'%(resultdir_for_day(day),
                                     (6 if ipv6 else 4),host)


def prepare_bgp(ipv6=False):
        """
        Runs Cisco parser and parse files from data like
        data/marge/bgp-ipv4-2014-04-01-01-17-01.txt.bz2
        and creates
        results/2014-04-01/bgp4-marge.pickle
        Returns list of Time objects.
        """

        import cisco

        out_days = []

        for host in BGP_HOSTS:
                for fn in common.enumerate_files(BGP_DATA[host], "bgp-%s-[0-9-]+\.txt.bz2"%
                                                 ("ipv6" if ipv6 else "ipv4")):
                        t = common.Day(common.parse_bgp_filename(fn)[1:4])
                        out_days.append(t)
                        common.d('BGP in:', fn, 'time:', t)
                        outdir = resultdir_for_day(t)
                        outfile = bgp_pickle_for_day(t,host,ipv6)

                        if os.path.isfile(outfile):
                                common.d('BGP out:', outfile, 'exists. Skip.')
                        else:
                                common.d('BGP out:', outfile)
                                cisco.gen_bgp_pickle(fn, outfile)
        return out_days



def gen_bgp_global(host, days, ipv6):
        """
        """

        import bgp
        bgp.module_run(host, days, bgp_pickle_for_day, resultdir_for_day, ipv6)



def main():
        for ipv6 in [False,True]:
                bgp_days = sorted(prepare_bgp(ipv6))
                for host in BGP_HOSTS:
                        gen_bgp_global(host, bgp_days, ipv6)
                               


if __name__ == '__main__':
    main()
