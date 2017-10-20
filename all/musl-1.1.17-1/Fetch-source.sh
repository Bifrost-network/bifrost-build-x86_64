#!/bin/bash

SRC=musl-1.1.17.tar.gz
DST=/var/spool/src/$SRC
SHA=1beaab2d091c2d6269e4c461fd0243232cc9ecebad53996a65304a8671a7250c

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k http://www.musl-libc.org/releases/$SRC
