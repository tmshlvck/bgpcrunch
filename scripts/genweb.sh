#!/bin/bash

DIR="../results/"
SRC="/tmp/charts.txt"
URL_PREFIX=""


find $DIR -name "*.png" > $SRC
find $DIR -name "*.txt" >> $SRC

### Global

cat <<EOF
<!DOCTYPE html>
<html>
<head>
<title>BGPCrunch results</title>
</head>
<body>
EOF

cat << EOF
<h1>Baseline results</h1>
<h2>BGP table timeline</h2>
<h3>Prefix count</h3>

<figure>
<img src="${URL_PREFIX}pfxcount4-sum.png">
<figcaption>IPv4 prefixes in BGP</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}pfxcount6-sum.png">
<figcaption>IPv6 prefixes in BGP</figcaption>
</figure>

<h3>Average path length</h3>

<figure>
<img src="${URL_PREFIX}pathlen4-3d.png">
<figcaption>IPv4 BGP path length per prefix length</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}pathlen4-avg.png">
<figcaption>IPv4 BGP average path length</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}pathlen6-3d.png">
<figcaption>IPv6 BGP path length per prefix length</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}pathlen6-avg.png">
<figcaption>IPv6 BGP average path length</figcaption>
</figure>

EOF

# BGP basic stats

echo "<h2>IPv4 BGP timeline of path length per prefix length</h2>"
echo "<p>["
files=( `grep -E "pathlen4-[0-9]+\.png" $SRC | sort -t '-' -n -k2` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/(pathlen4-[0-9]+\.png)#\1#'`
    c=`echo $f | sed -r 's#.*/pathlen4-([0-9]+)\.png#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$c</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>IPv6 BGP timeline of path length per prefix length</h2>"
echo "<p> ["
files=(  `grep -E "pathlen6-[0-9]+\.png" $SRC | sort -t '-' -n -k2` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/(pathlen6-[0-9]+\.png)#\1#'`
    c=`echo $f | sed -r 's#.*/pathlen6-([0-9]+)\.png#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$c</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>IPv4 BGP timeline of prefix count per prefix length</h2>"
echo "<p> ["
files=( `grep -E "pfxcount4-[0-9]+\.png" $SRC | sort -t '-' -n -k2` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/(pfxcount4-[0-9]+\.png)#\1#'`
    c=`echo $f | sed -r 's#.*/pfxcount4-([0-9]+)\.png#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$c</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>IPv6 BGP timeline of prefix count per prefix length</h2>"
echo "<p> ["
files=( `grep -E "pfxcount6-[0-9]+\.png" $SRC | sort -t '-' -n -k2` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/(pfxcount6-[0-9]+\.png)#\1#'`
    c=`echo $f | sed -r 's#.*/pfxcount6-([0-9]+)\.png#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$c</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv4 BGP average path length by prefix length</h2>"
echo "<p> ["
files=( `grep -E "marge-pathlen4.png" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv6 BGP average path length by prefix length</h2>"
echo "<p> ["
files=( `grep -E "marge-pathlen6.png" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv4 BGP path length report by prefix length (text)</h2>"
echo "<p> ["
files=( `grep -E "marge-pathlen4.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv6 BGP path length report by prefix length (text)</h2>"
echo "<p> ["
files=( `grep -E "marge-pathlen6.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"


cat << EOF
<h2>RIR service regions share</h2>
<h3>Prefix counts per RIR</h3>

<figure>
<img src="${URL_PREFIX}rirpfxcount4-marge.png>
<figcaption>IPv4 BGP prefix count per RIR</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}rirpfxcount6-marge.png">
<figcaption>IPv6 BGP prefix count per RIR</figcaption>
</figure>
EOF

echo "<h2>Daily IPv4 BGP RIR share report (text)</h2>"
echo "<p> ["
files=( `grep -E "rirstats4-marge.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv6 BGP RIR share report (text)</h2>"
echo "<p> ["
files=( `grep -E "rirstats6-marge.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"


cat << EOF
<h3>Observed avgerage pathlen per RIR</h3>

<figure>
<img src="${URL_PREFIX}rirpfxlen4-marge.png">
<figcaption>IPv4 BGP average path length per RIR</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}rirpfxlen6-marge.png">
<figcaption>IPv6 BGP average path length per RIR</figcaption>
</figure>
EOF


# Verification results

cat << EOF
<h1>BGP matching results</h1>

<h2>BGP origin verification results</h2>

<figure>
<img src="${URL_PREFIX}bgp2routes4.png">
<figcaption>IPv4 BGP origin verification results</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}bgp2routes6.png">
<figcaption>IPv6 BGP origin verification results</figcaption>
</figure>
EOF

### Daily route results

echo "<h2>Daily IPv4 BGP route matching report (text)</h2>"
echo "<p> ["
files=( `grep -E "bgp2routes.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv6 BGP route matching report (text)</h2>"
echo "<p> ["
files=( `grep -E "bgp2routes6.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

# Common path results

cat << EOF
<h2>BGP path verification results</h2>
<h3>IPv4</h3>

<figure>
<img src="${URL_PREFIX}bgp2paths4.png">
<figcaption>Path verification results</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}bgp2paths-detail4.png">
<figcaption>Path verification details</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}bgp2paths-stats4.png">
<figcaption>Path verification errors per path</figcaption>
</figure>

<h3>IPv6</h3>

<figure>
<img src="${URL_PREFIX}bgp2paths6.png">
<figcaption>Path verification results</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}bgp2paths-detail6.png">
<figcaption>Path verification details</figcaption>
</figure>

<figure>
<img src="${URL_PREFIX}bgp2paths-stats6.png">
<figcaption>Path verification errors per path</figcaption>
</figure>

EOF


### Daily path results

echo "<h2>IPv4 BGP full paths matched against RIPE DB</h2>"
echo "<p>["
files=( `grep -E "/[0-9-]+/bgp2paths.png" $SRC | sort -d` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>IPv6 BGP full paths matched against RIPE DB</h2>"
echo "<p>["
files=( `grep -E "/[0-9-]+/bgp2paths6.png" $SRC | sort -d` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>IPv4 BGP paths matched against RIPE DB by prefix length</h2>"
echo "<p>["
files=( `grep -E "bgppathbypfxlen4.png" $SRC | sort -d` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"
    
echo "<h2>IPv6 BGP paths matched against RIPE DB by prefix length</h2>"
files=( `grep -E "bgppathbypfxlen6.png" $SRC | sort -d` )
for f in ${files[@]}; do
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv4 BGP path matching report (text)</h2>"
echo "<p> ["
files=( `grep -E "bgp2paths.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

echo "<h2>Daily IPv6 BGP path matching report (text)</h2>"
echo "<p> ["
files=( `grep -E "bgp2paths6.txt" $SRC | sort -d` )
for f in ${files[@]}; do
    d=`echo $f | sed -r 's#.*/([0-9-]+)/.*#\1#'`
    fn=`echo $f | sed -r 's#.*/([0-9-]+/.*)$#\1#'`
    echo -n "<a href="${URL_PREFIX}$fn">$d</a>"
    if [ "$f" != "${files[${#files[@]}-1]}" ]; then
	 echo " | "
    fi
done
echo "]</p>"

cat <<EOF
<h2>Route violations timeline</h2>
<p>
<a href="${URL_PREFIX}route_violations_timeline/">IPv4</a>
</p>
<p>
<a href="${URL_PREFIX}route6_violations_timeline/">IPv6</a>
</p>
EOF


cat <<EOF
</body>
</html>
EOF

rm -f $SRC
