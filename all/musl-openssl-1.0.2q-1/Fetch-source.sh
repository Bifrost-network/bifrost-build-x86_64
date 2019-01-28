#!/bin/bash

SRC=openssl-1.0.2q.tar.gz
DST=/var/spool/src/$SRC
SHA=78e84a9dc5ca747abb86f0b39b052215df928060762844f0837773c651c921b0

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.openssl.org/source/$SRC
