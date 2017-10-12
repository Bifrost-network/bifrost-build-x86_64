#!/bin/bash

SRC=mod_md-1.0.0.tar.gz
DST=/var/spool/src/$SRC
SHA=7b8625c7558c2f294c277799e7596e23d617e4d537a0ea62764694c736fd7cb7

pkg_install tarmd-1.2-1 || exit 2
pkg_install curl-7.51.0-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://github.com/icing/mod_md/releases/download/v1.0.0/$SRC
