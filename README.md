bgpcrunch
=========

BGP cuncher & stats generator

Dependencies:

 * Python (2.7)
 * ipaddr Python module
 * gnuplot


Needed input:

BGP crunch needs BGP table dumps in Cisco format (output of commands
"show bgp ipv4 unicast" and "show bgp ipv6 unicast") and packed
RIPE DB snapshot. RIPE DB snapshot can be obtained (2015/05/25) from
ftp://ftp.ripe.net/ripe/dbase/split/ . And we need IANA IP address
assignments in CSV form from:
http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv
and
http://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv
.


The data directory should look like this:

```
./data
  ./data/marge
    ./data/marge/bgp-ipv4-2014-04-01-01-17-01.txt.bz2
    ./data/marge/bgp-ipv4-2014-04-02-01-17-03.txt.bz2
    ./data/marge/bgp-ipv4-2014-04-03-01-17-02.txt.bz2
    ./data/marge/bgp-ipv6-2014-04-01-01-17-01.txt.bz2
    ./data/marge/bgp-ipv6-2014-04-02-01-17-03.txt.bz2
    ./data/marge/bgp-ipv6-2014-04-03-01-17-02.txt.bz2
  ./data/ripe
    ./data/ripe/ripedb-2014-04-02-02-19-01.tar.bz2
  ./data/ipv4-address-space.csv
  ./data/ipv6-unicast-address-assignments.csv
```

Please note: We have BGP data for more days than RIPE DB snapshots. It is
not a problem, BGP cruncher will find intersection of available dates and
attempt to generate results only for days that we have complete data for.


Basic usage:

```
cd scripts
./run_all.py
```

Output:

It generates extensive output to resutls directory. The output
consists of:
- byproducts - *.picke files
- daily outputs that covers one day analysis of BGP (text and plots)
- summary analysis for each days in form of plots
- route object violation timeline (text) in route_violations_timeline{,6}


More advanced usage:
The suite supports spreading the computation on more computers to
paralelize it not only on the local multithreading basis but also
using more distinct servers in parallel. How to:

- Run ./run_all.py --preprocess on the main server
- Run ./run_all.py --listdays > days.txt
- Partition days.txt into more files containing non-overlapping subsets,
say workpackage0.txt .. workpackage7.txt
- Mount the bgpcrunch root to servers0..7 to the same path as it is on
the primary server using NFS or SSHFS.
- Run ./run_all.py --wp workpackageN.txt on server N for N in 0..7
- Run ./run_all.py --postprocess on the master server

