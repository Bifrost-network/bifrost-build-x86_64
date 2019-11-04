#!/bin/bash

SRC=httpd-2.4.41.tar.bz2
DST=/var/spool/src/$SRC
SHA=77dc5cabf70af632c042ead101b9e3522149e89307bdd038f93590841eeb31ee

pkg_install curl-7.51.0-1 || exit 2
pkg_install tarmd-1.2-1 || exit 2
[ -s "$DST" ] || tarmd $SHA $DST curl -L -k https://archive.apache.org/dist/httpd/$SRC
