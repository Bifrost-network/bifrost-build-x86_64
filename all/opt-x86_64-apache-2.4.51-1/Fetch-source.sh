#!/bin/bash

SRC=httpd-2.4.51.tar.bz2
DST=/var/spool/src/$SRC
SHA=cd6022d349e9eaaa0a2b15ee55bb50c4d0b920520ec50b07b711f3599eddba1b

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
