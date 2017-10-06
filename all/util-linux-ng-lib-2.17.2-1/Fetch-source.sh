#!/bin/bash

SRC=util-linux-ng-2.17.2.tar.bz2
DST=/var/spool/src/$SRC
SHA=b9480d7721e1de63d0c64f0aef71fa7b80edd0c1b74e11687f17cc0271fb99fa

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.kernel.org/pub/linux/utils/util-linux/v2.17/$SRC

