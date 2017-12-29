#!/bin/bash

SRC=mod_md-1.1.6.tar.gz
DST=/var/spool/src/$SRC
SHA=8183031d4a509f0e025d4e3f07786c8a4c90822f439381f54876610878051fcf

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/icing/mod_md/releases/download/v1.1.6/$SRC
