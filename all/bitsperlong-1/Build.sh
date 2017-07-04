#!/bin/bash

SRCVER=bitsperlong
PKG=$SRCVER-1 # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
BUILDDIR=/var/tmp/src/$SRCVER
DST="/var/tmp/install/$PKG"

#########
# Simple inplace edit with sed.
# Usage: sedit 's/find/replace/g' Filename
function sedit {
    sed "$1" $2 > /tmp/sedit.$$
    cp /tmp/sedit.$$ $2
    rm /tmp/sedit.$$
}

pkg_uninstall # Uninstall any dependencies used by Fetch-source.sh

# Install into dir under /var/tmp/install
rm -rf "$DST"
mkdir -p $DST/usr/include/asm || exit 1
cp $PKGDIR/bitsperlong.h $DST/usr/include/asm || exit 1

#########
# Make package
cd $DST || exit 1
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
pkg_uninstall
exit 0
