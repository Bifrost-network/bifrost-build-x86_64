#!/bin/bash

SRC=openssl-0.9.8x.tar.gz
DST=/var/spool/src/$SRC
SHA=0123c4150945d5be274de6a19c070cf4842ba81263f862fc772c64d9d527b691

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k http://ftp.openssl.org/source/old/0.9.x/$SRC
