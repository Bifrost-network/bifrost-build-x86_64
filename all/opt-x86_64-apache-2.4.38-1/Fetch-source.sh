#!/bin/bash

SRC=httpd-2.4.38.tar.bz2
DST=/var/spool/src/$SRC
SHA=740f923c86567a1cf8e089e6d0903d39c5172f12a4adff7b35c77d2aff6ef264

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
