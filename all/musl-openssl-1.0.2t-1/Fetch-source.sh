#!/bin/bash

SRC=openssl-1.0.2t.tar.gz
DST=/var/spool/src/$SRC
SHA=c1c3e70e258008319d189762f29064422f4fc1518bb870046eeb71e1ce36eca9

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.openssl.org/source/$SRC
