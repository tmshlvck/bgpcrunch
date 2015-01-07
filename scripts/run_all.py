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
        ifn=get_text_fh(infile)
        hist=parse_paths.get_pfx_histogram_lines(ifn.readlines(),ipv6)
        with open(outfile,'w') as of:
            of.write(str(parse_paths.get_pfx_histogram(hist)))


def main():
    # IPv4
    for t in common.enumerate_available_times(False):
        bgpfile=common.get_bgp_file(t,False)
        resultdir=common.get_result_dir(t)

        print "Processing time "+str(t)+"..."
        print "BGP file: "+str(bgpfile)
        print "Result dir: "+str(resultdir)

        generate_histogram(bgpfile,resultdir+'/histogram.txt',False)

#        print get_ripe_file(t)


if __name__ == '__main__':
    main()
