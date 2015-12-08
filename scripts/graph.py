#!/usr/bin/env python
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

import subprocess


GNUPLOT_BIN='/usr/bin/gnuplot5'
SCRIPT_SUFFIX='.gnu'
OUTPUT_TERM='pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 800,600'
OUTPUT_SUFFIX='png'
COMMON_HEADER=''

def gen_2dplot(header,data,filepfx):
    """ Low level function. Do not use."""

    if len(data)==0:
        raise Exception("Can not generate empty plot! Gnuplot will fail subsequently.")
    
    with open(filepfx+SCRIPT_SUFFIX,'w') as f:
        f.write(header)
        # nasty hack for naughty gnuplot
        for (dci,notused) in enumerate(data[0]): # dci = data column index
            if dci == 0:
                continue
            for dl in data:
                f.write(str(dl[0])+' '+str(dl[dci])+"\n")
            f.write("e\n")

    subprocess.call([GNUPLOT_BIN,filepfx+SCRIPT_SUFFIX])


def gen_lineplot(data,filepfx,title='Anonymous graph',xlabel='Date',ylabel='y',xrange=None,yrange=None):
    """ Generate one line plot.
    data = i.e. [('2014-01-01',1),('2014-01-02',2),('2014-01-03',3)]
    filepfx is the prefix (path) for resulting files.
    filepfx='/tmp/testgraph' -> /tmp/testgraph.gnu and /tmp/testgraph.png
    ... TODO
    """

    
    HEADER=COMMON_HEADER+'''set term '''+OUTPUT_TERM+'''
set output "''' + filepfx + '.' + OUTPUT_SUFFIX + '''"
set style line 1 lc rgb "#dd181f" lt 1 lw 2 pt 7 ps 1.5
set xlabel "'''+ xlabel + '''"
set ylabel "''' + ylabel + '''"
''' + ('set xrange ['+str(xrange[0])+','+str(xrange[1])+']' if xrange else '')+'''
'''+ ('set yrange ['+str(yrange[0])+','+str(yrange[1])+']' if yrange else '')+'''
'''+('set xdata time' if xlabel=='Date' else '')+'''
set timefmt "%Y-%m-%d"
set offset 0, 0, graph 0.1, 0

plot "-" using 1:2 with lines ls 1 title "''' + title + '''"
'''
    return gen_2dplot(HEADER,data,filepfx)


def gen_multilineplot(data,filepfx,xlabel='Date',ylabel='y',legend=[],xrange=None,yrange=None):
    """ Generate multiple-line plot.
    data = i.e. [('2014-01-01',1,2,3),('2014-01-02',2,3,4),('2014-01-03',3,4,5)]
    filepfx is the prefix (path) for resulting files.
    filepfx='/tmp/testgraph' -> /tmp/testgraph.gnu and /tmp/testgraph.png
    ... TODO
    """

    
    HEADER=COMMON_HEADER+'''set term '''+OUTPUT_TERM+'''
set output "''' + filepfx + '.'+OUTPUT_SUFFIX+'''"
#set style line 1 lc rgb "#dd181f" lt 1 lw 2 pt 7 ps 1.5
set xlabel "'''+ xlabel + '''"
set ylabel "''' + ylabel + '''"
''' + ('set xrange ['+str(xrange[0])+','+str(xrange[1])+']' if xrange else '')+'''
'''+ ('set yrange ['+str(yrange[0])+','+str(yrange[1])+']' if yrange else '')+'''
'''+('set xdata time' if xlabel=='Date' else '')+'''
set timefmt "%Y-%m-%d"
set offset 0, 0, graph 0.1, 0

plot'''

    if not data:
        raise Exception("Can not plot no data. We need at least one point to set the multiline graph.")

    for (i,d) in enumerate(data[0]):
        if i==0:
            continue

        l = legend[i-1] if len(legend)>=i else 'y'+str(i)
        HEADER+=('"-"' if i==1 else '""')+' using 1:2 with lines title "' + l +'"'
        if i<len(data[0])-1:
            HEADER+=', '
        else:
            HEADER+="\n"

    return gen_2dplot(HEADER,data,filepfx)

    

def gen_3dplot(data,filepfx,title='Anonymous graph',xlabel='Date',ylabel='y',zlabel='z'):
    """ Generate 3D net plot.
    TODO
    filepfx is the prefix (path) for resulting files.
    filepfx='/tmp/testgraph' -> /tmp/testgraph.gnu and /tmp/testgraph.png
    ... TODO
    """

    
    if len(data)==0 or len(data[0])!=3:
        raise Exception("Can not generate empty plot! Gnuplot will fail subsequently.")
    
    dsgridx='30'
    dsgridy='60'
   
    HEADER=COMMON_HEADER+'''set term '''+OUTPUT_TERM+'''
set output "''' + filepfx + '.'+OUTPUT_SUFFIX+'''"
set style line 1 lc rgb "#dd181f" lt 1 lw 2 pt 7 ps 1.5
set dgrid3d '''+dsgridx+','+dsgridy+'''
set hidden3d
set xlabel "''' + xlabel + '''"
set ylabel "'''+ ylabel +'''"
set zlabel "''' + zlabel + '''"
'''+('set xdata time' if False and xlabel=='Date' else '')+'''
set timefmt "%Y-%m-%d"

splot "-" using 1:2:3 with lines ls 1 title "''' + title + '''"
'''
    
    with open(filepfx+SCRIPT_SUFFIX,'w') as f:
        f.write(HEADER)
        lastdate=data[0][0]
        for d in data:
            if not lastdate==d[0]:
#                f.write("\n")
                lastdate=d[0]
            f.write(str(d[0])+' '+str(d[1])+' '+str(d[2])+"\n")

    subprocess.call([GNUPLOT_BIN,filepfx+SCRIPT_SUFFIX])






def test():
    """ Unit self-test. """
    
    fn='/tmp/testgraph1'
    print "Generating files "+fn+str([SCRIPT_SUFFIX,OUTPUT_SUFFIX])
    gen_lineplot([('2014-01-01',1),('2014-01-02',2),('2014-01-03',3)],fn)

    fn='/tmp/testgraph2'
    print "Generating files "+fn+str([SCRIPT_SUFFIX,OUTPUT_SUFFIX])
    gen_multilineplot([('2014-01-01',1,2,3),('2014-01-02',2,3,4),('2014-01-03',3,2,8)],fn)
    
    

def main():
    import sys
    if '-t' in sys.argv:
        test()
    else:
        raise Exception("This is a module, not a script. Use -t to run self-test.")

if __name__ == '__main__':
    main()
