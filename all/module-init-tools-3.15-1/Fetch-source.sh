#!/bin/bash

SRC=module-init-tools-3.15.tar.bz2
DST=/var/spool/src/$SRC
SHA=98e8eb9bfc03dd1c362506d371700e64ecaaecf4d1a3bf6ee8957ca550b22014

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.kernel.org/pub/linux/utils/kernel/module-init-tools/$SRC

