#!/bin/bash

SRC=curl-7.56.0.tar.bz2
DST=/var/spool/src/$SRC
SHA=90532adbf2e40e6a5d6b084c1b6bbecda867b69b0757551e4226f000994e8ea4

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://curl.haxx.se/download/$SRC
