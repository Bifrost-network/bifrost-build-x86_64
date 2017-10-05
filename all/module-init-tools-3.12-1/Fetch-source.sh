#!/bin/bash

SRC=module-init-tools-3.12.tar.bz2
DST=/var/spool/src/$SRC
SHA=4409a1fd92538c5bf255b7117abb84e617057f5d3f6020d2b01d156de833dc78

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.kernel.org/pub/linux/utils/kernel/module-init-tools/$SRC

