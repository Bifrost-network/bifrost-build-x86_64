#!/bin/bash

APACHEVER=2.4.27
SRCVER=httpd-$APACHEVER
PKG=musl-apache-devel-$APACHEVER-1 # with build version

# PKGDIR is set by 'pkg_build'. Usually "/var/lib/build/all/$PKG".
PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.bz2
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

#########
# Fetch sources
./Fetch-source.sh || exit 1
pkg_uninstall # Uninstall any dependencies used by Fetch-source.sh

#########
# Install dependencies:
# pkg_available dependency1-1 dependency2-1
pkg_install musl-zlib-1.2.8-2 || exit 2
pkg_install musl-openssl-1.0.2l-1 || exit 2
pkg_install musl-apr-1.5.2-1 || exit 2
pkg_install musl-apr-util-1.5.3-1 || exit 2
pkg_install musl-pcre-8.30-2 || exit 2
pkg_install musl-libxml2-2.9.3-1 || exit 2
pkg_install musl-nghttp2-1.25.0-1 || exit 2
pkg_install musl-jansson-2.10-1 || exit 2
pkg_install musl-curl-devel-7.55.1-1 || exit 2
pkg_install musl-1.1.16-1 || exit 2 
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
cd $(dirname $BUILDDIR); tar xf $SRC

#########
# Patch
cd $BUILDDIR || exit 1
libtool_fix-1

patch -p0 < $PKGDIR/mod_ssl_md-2.4.x-v2.diff || exit 1
patch -p3 < $PKGDIR/mod_proxy_balancer.pat || exit 1
patch -p1 < $PKGDIR/override.pat || exit 1
patch -p1 < $PKGDIR/socache.pat || exit 1
patch -p0 < $PKGDIR/layout.pat || exit 1
patch -p0 < $PKGDIR/mod_proxy_html.pat || exit 1
cp $PKGDIR/mod_limitipconn.c modules/aaa || exit 1
cp $PKGDIR/mod_lbmethod_byip.c modules/proxy || exit 1

patch -p1 < $PKGDIR/httpd-debug.pat || exit 1

# Bump maximum size of socache
sed -i 's/64/2048/' modules/cache/mod_socache_shmcb.c || exit 1

#########
# Configure

LIBS="-lcurl -ljansson" B-configure-1 --prefix=/opt/musl --disable-nls --enable-static-support\
 --enable-http2 --enable-nghttp2-staticlib-deps\
 --with-z=/opt/musl\
 --with-apr=/opt/musl/bin/apr-1-config --with-apr-util=/opt/musl/bin/apu-1-config\
 --with-pcre=/opt/musl/bin/pcre-config --with-libxml2=/opt/musl/include/libxml2\
 --with-module=aaa:limitipconn,proxy:lbmethod_byip \
 --enable-cache-socache \
 --enable-lbmethod-byrequests --enable-lbmethod-bybusyness --enable-lbmethod-heartbeat\
 --enable-heartbeat --enable-heartmonitor --enable-proxy-fdpass\
 --with-mpm=event --enable-suexec\
 --enable-mods-static=all --enable-ssl --enable-proxy --enable-proxy-connect\
 --enable-proxy-html\
 --enable-proxy-http --enable-proxy-ajp --enable-proxy-balancer \
 --disable-shared --enable-static --sysconfdir=/opt/apache/etc\
 --localstatedir=/var || exit 1
[ -f config.log ] && cp -p config.log /var/log/config/$PKG-config.log

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat

#########
# Compile
#make V=1 || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make install-include DESTDIR=$DST # --with-install-prefix may be an alternative

#########
# Check result
cd $DST
# [ -f usr/bin/myprog ] || exit 1
# (ldd sbin/myprog|grep -qs "not a dynamic executable") || exit 1

#########
# Clean up
cd $DST

#########
# Make package
cd $DST
tar czf /var/spool/pkg/$PKG.tar.gz .

#########
# Cleanup after a success
cd /var/lib/build
[ "$DEVEL" ] || rm -rf "$DST"
[ "$DEVEL" ] || rm -rf "$BUILDDIR"
pkg_uninstall
exit 0
