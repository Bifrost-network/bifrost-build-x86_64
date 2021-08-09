#!/bin/bash

SRC=httpd-2.4.48.tar.bz2
DST=/var/spool/src/$SRC
SHA=56299975d8cbc80d00198217268511c1d5f3408e1abab4ca36d85bfa957add24

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
