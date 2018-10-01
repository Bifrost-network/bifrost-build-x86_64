#!/bin/bash

V=4.14.71
VER=kernel-$V
SRC=kernel-$V.tar.gz
DST=/var/spool/src/$SRC
SHA=585c2bde1242f0b4c047de921f421c148b618dbd390ed5ba0a90b286910cae02

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-$V.tar.gz
