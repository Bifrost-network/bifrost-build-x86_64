#!/bin/bash

SRC=mod_md-0.9.1.tar.gz
DST=/var/spool/src/$SRC
SHA=dbe493c9129e02b3188265de9bbb402ca2aaa7afe6a2a29c7bc9210cd17b0c27

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/icing/mod_md/releases/download/v0.9.1/$SRC
