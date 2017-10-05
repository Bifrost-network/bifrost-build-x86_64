#!/bin/bash

SRC=git-2.14.2.tar.gz
DST=/var/spool/src/$SRC
SHA=d0710bdf0625a93def26246fa7cde74e88a0e89ebbceedb6f191a79abd695f74

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://www.kernel.org/pub/software/scm/git/$SRC
