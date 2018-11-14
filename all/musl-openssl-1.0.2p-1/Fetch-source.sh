#!/bin/bash

SRC=openssl-1.0.2p.tar.gz
DST=/var/spool/src/$SRC
SHA=081f84ff0fd8133f31133ff31eb81bb854956b2284377290f18ba9f9154922c2

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k ftp://ftp.openssl.org/source/$SRC || tarmd $SHA $DST curl -L -k http://ftp.openssl.org/source/old/1.0.2/$SRC
