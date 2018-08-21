#!/bin/bash

V=4.14.65
VER=kernel-$V
SRC=kernel-$V.tar.gz
DST=/var/spool/src/$SRC
SHA=1566f6cb96a5218429e45c84c5d89d47e5b376a23336c36c41bb14d2a4fad199

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-$V.tar.gz
