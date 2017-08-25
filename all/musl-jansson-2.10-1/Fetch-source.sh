#!/bin/bash

SRC=jansson-2.10.tar.gz
DST=/var/spool/src/$SRC
SHA=0a8a1ba8b881642c966afe2f4fad739ecbeb035f711544d4c499b7645bc99164

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k http://www.digip.org/jansson/releases/$SRC
