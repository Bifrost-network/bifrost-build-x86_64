#!/bin/bash

SRC=httpd-2.4.29.tar.bz2
DST=/var/spool/src/$SRC
SHA=04af11a74e14cf9f9000fa5a9c5ec0055ca0780e5932ec7cffefd3dbb5fbfaf0

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
