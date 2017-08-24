#!/bin/bash

SRC=httpd-2.4.27.tar.bz2
DST=/var/spool/src/$SRC
SHA=81b1efcb5944fd2587c0106423aa9cb541154b2720ce4ac7144d42dcff868112

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
