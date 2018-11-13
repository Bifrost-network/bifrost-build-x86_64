#!/bin/bash

SRC=apr-1.6.5.tar.bz2
DST=/var/spool/src/$SRC
SHA=bfa941cfad703610d52af098fa5318d8f5b3bf9a1f8175d1853b047a7682b689

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/apr/$SRC
