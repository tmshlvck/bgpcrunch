#!/bin/bash

sed -i 's/^set term pngcairo .*/set terminal postscript eps enhanced monochrome font \"Helvetica,10\"/' $1

sed -i -r 's#^set output \".*/([^/]+)\.png\"#set output "\1.eps"#' $1

