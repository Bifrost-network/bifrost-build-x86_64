#!/bin/bash

SRC=musl-1.1.24.tar.gz
DST=/var/spool/src/$SRC
SHA=f3ef9e139f60050148d21c00f6c083f80a81784d81c0e3cb4cbed67241954ed5

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k http://www.musl-libc.org/releases/$SRC
