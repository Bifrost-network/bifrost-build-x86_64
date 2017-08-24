#!/bin/bash

SRC=nghttp2-1.25.0.tar.bz2
DST=/var/spool/src/$SRC
SHA=c827ade64030c0658992140b04fcfa11ba9c1a8afaff3a2f568a7e8d901219b2

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/nghttp2/nghttp2/releases/download/v1.25.0/$SRC
