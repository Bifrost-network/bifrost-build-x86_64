#!/bin/bash

SRC=curl-7.55.1.tar.bz2
DST=/var/spool/src/$SRC
SHA=0aa7605fcdeb377f63a74ffda7e08e625206c34f4aae9abae200570444d7bab3

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://curl.haxx.se/download/$SRC
