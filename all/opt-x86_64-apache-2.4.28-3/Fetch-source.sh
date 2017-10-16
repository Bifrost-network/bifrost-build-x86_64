#!/bin/bash

SRC=httpd-2.4.28.tar.bz2
DST=/var/spool/src/$SRC
SHA=7cb3f011bd52e440cca851fa3dae77da2369afa5d383f699833efb324ce76029

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
