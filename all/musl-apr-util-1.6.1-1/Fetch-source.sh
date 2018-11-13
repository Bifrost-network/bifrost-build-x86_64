#!/bin/bash

SRC=apr-util-1.6.1.tar.bz2
DST=/var/spool/src/$SRC
SHA=cb7e97810b5990163f2cc897fdf471d78f6a9dd7df163b75986ca0fce1715c9c

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/apr/$SRC

