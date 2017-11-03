#!/bin/bash

SRC=musl-1.1.18.tar.gz
DST=/var/spool/src/$SRC
SHA=f3de68f0c5adb663d2612972ce938a2658497862433678ff8e769b922bdc7224

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k http://www.musl-libc.org/releases/$SRC
