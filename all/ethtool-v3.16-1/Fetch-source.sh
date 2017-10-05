#!/bin/bash

V=v3.16
VER=ethtool-$V
SRC=ethtool-$V.tar.gz
DST=/var/spool/src/$SRC
TDST=/var/spool/src/$SRC.dl
SHA=779676d74d8401a6782cb29fef1fe228b36a8d9e772d72189ca3b91f78ddc13c

if [ ! -s "$DST" ]; then
    pkg_install passwd-file-1 || exit 2
    pkg_install git-2.14.2-1 || exit 2
    pkg_install openssh-5.5p1-1 || exit 2
    pkg_install tarmd-1.2-1 || exit 2
    cd /tmp
    rm -rf $VER
    /opt/git/bin/git -c http.sslVerify=false clone -4 http://git.kernel.org/pub/scm/network/ethtool/ethtool.git $VER || exit 1
    cd $VER || exit 1
    /opt/git/bin/git checkout $V || exit 1
    rm -rf .git
    cd /tmp
    tar czf $TDST $VER
    rm -rf $VER
    tarmd $SHA $DST cat $TDST || exit 1
    rm -f $TDST
fi

