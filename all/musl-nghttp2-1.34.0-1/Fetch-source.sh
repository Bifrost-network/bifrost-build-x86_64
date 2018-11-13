#!/bin/bash

SRC=nghttp2-1.34.0.tar.bz2
DST=/var/spool/src/$SRC
SHA=61c2a4a97ceb299f7acb483ccce3431ec1c6166c12ef163e32c56b570b83ad18

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/nghttp2/nghttp2/releases/download/v1.34.0/$SRC
