#!/bin/bash

VER=0.9.1
SRCVER=libmd-$VER
PKG=musl-$SRCVER-1 # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/mod_md-$VER.tar.gz
BUILDDIR=/var/tmp/src/mod_md-$VER
DST="/var/tmp/install/$PKG"

#########
# Simple inplace edit with sed.
# Usage: sedit 's/find/replace/g' Filename
function sedit {
    sed "$1" $2 > /tmp/sedit.$$
    cp /tmp/sedit.$$ $2
    rm /tmp/sedit.$$
}

#########
# Fetch sources
./Fetch-source.sh || exit $?
pkg_uninstall # Uninstall any dependencies used by Fetch-source.sh

#########
# Install dependencies:
# pkg_available dependency1-1 dependency2-1
# pkg_install dependency1-1 || exit 2
# pkg_install groff-1.21-1 || exit 2 # Needed to convert man-pages: see below

pkg_install musl-openssl-1.0.2l-1 || exit 2
pkg_install musl-jansson-2.10-1 || exit 2
pkg_install musl-curl-devel-7.55.1-1 || exit 2
pkg_install pkg-config-0.23-1 || exit 2
pkg_install musl-apr-1.5.2-1 || exit 2
pkg_install musl-apr-util-1.5.3-1 || exit 2
pkg_install musl-zlib-1.2.8-2 || exit 2
pkg_install musl-apache-devel-2.4.27-1 || exit 2

# Compile against musl:
pkg_install musl-1.1.16-1 || exit 2 
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR || exit 1
libtool_fix-1
# patch -p1 < $PKGDIR/mypatch.pat
sed -i 's,test/Makefile ,,' configure
sed -i 's,test/test.ini ,,' configure

#########
# Configure
LIBS="-lapr-1 -lssl -lcrypto -lz" $PKGDIR/B-configure-3 --prefix=/opt/musl --with-apxs=$PKGDIR/apxs || exit 1
[ -f config.log ] && cp -p config.log /var/log/config/$PKG-config.log

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat
sed -i 's/src test/src/' Makefile

#########
# Compile
make V=1 || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"

mkdir -p $DST/opt/musl/lib $DST/opt/musl/include || exit 1
cp ./src/.libs/libmd.a $DST/opt/musl/lib
cp ./src/md*h  $DST/opt/musl/include

#########
# Convert man-pages
cd $DST || exit 1
# for f in $(find . -path \*man/man\*); do if [ -f $f ]; then groff -T utf8 -man $f > $f.txt; rm $f; fi; done

#########
# Check result
cd $DST || exit 1
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST || exit 1
# rm -rf opt/musl/share
# rm -rf opt/musl/man
[ -d opt/musl/bin ] && strip opt/musl/bin/*
[ -d opt/musl/sbin ] && strip opt/musl/sbin/*
[ -d opt/musl/libexec ] && strip opt/musl/libexec/*

#########
# Make package
cd $DST || exit 1
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$BUILDDIR"
pkg_uninstall
exit 0
