#!/bin/bash

SRC=openssl-1.1.1.tar.gz
DST=/var/spool/src/$SRC
SHA=c63ab7e6e65475236bd81e3de8bd599b861e4cccf024391a2ec5f48aa8e04274

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST /usr/bin/curl -L -k http://www.openssl.org/source/$SRC
