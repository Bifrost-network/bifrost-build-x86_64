#!/bin/bash

SRC=mod_md-0.7.0.tar.gz
DST=/var/spool/src/$SRC
SHA=9eeca0778a6e471a3191e00cf9ffbd85d6b118d098352fb0b29caa6c7de7122e

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/icing/mod_md/releases/download/v0.7.0/$SRC
