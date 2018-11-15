#!/bin/bash

SRC=httpd-2.4.37.tar.bz2
DST=/var/spool/src/$SRC
SHA=a0e889cf40337b0f4c461bf73cbb0f0ef7fc43d3ad84eb7f2ce24f51edbac65f

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
