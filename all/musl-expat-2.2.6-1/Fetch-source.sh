#!/bin/bash

SRC=expat-2.2.6.tar.bz2
DST=/var/spool/src/$SRC
SHA=afb0e23a2e74682001699144ab18388c8bd8b27c366ea2c403662ef2a64f4333

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/libexpat/libexpat/releases/download/R_2_2_6/$SRC

