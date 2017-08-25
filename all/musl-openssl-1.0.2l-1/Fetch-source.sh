#!/bin/bash

SRC=openssl-1.0.2l.tar.gz
DST=/var/spool/src/$SRC
SHA=7c4ccd4897062a126dae592a2366e3f120c6ef96ad198e2e645c4cce4b20ca21

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k ftp://ftp.openssl.org/source/$SRC || tarmd $SHA $DST curl -L -k http://ftp.openssl.org/source/old/1.0.2/$SRC
