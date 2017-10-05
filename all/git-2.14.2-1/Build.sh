#!/bin/bash

SRCVER=git-2.14.2
PKG=$SRCVER-1 # with build version

PKGDIR=${PKGDIR:-/var/lib/build/all/$PKG}
SRC=/var/spool/src/$SRCVER.tar.gz
BUILDDIR=/var/tmp/src/$SRCVER
DST="/var/tmp/install/$PKG"

#########
# Install dependencies:
pkg_install musl-openssl-1.0.2l-1 || exit 2
pkg_install musl-zlib-1.2.8-2 || exit 2
pkg_install musl-curl-devel-7.55.1-1 || exit 2
pkg_install perl-5.10.1-1 || exit 2

# Compile against musl:
pkg_install musl-1.1.16-1 || exit 2 
export CC=musl-gcc

#########
# Unpack sources into dir under /var/tmp/src
./Fetch-source.sh || exit 1
cd $(dirname $BUILDDIR) || exit 1
tar xf $SRC

#########
# Patch
cd $BUILDDIR || exit 1
libtool_fix-1
# patch -p1 < $PKGDIR/mypatch.pat

#########
# Configure
LIBS="-lz -lssl -lcrypto" CXXFLAGS="-Os -g" CFLAGS="-Os -g" LDFLAGS="-static -lssl -lcrypto" ./configure --prefix=/opt/git --with-curl || exit 1

#########
# Post configure patch
# patch -p0 < $PKGDIR/Makefile.pat
echo "NO_PERL=YesPlease" >> config.mak
echo "NO_NSEC=YesPlease" >> config.mak
echo "NO_PTHREADS=YesPlease" >> config.mak
echo "NO_TCLTK=YesPlease" >> config.mak
echo "NO_PYTHON=YesPlease" >> config.mak
echo "NO_GETTEXT=YesPlease" >> config.mak
#echo "NO_=YesPlease" >> config.mak

sed -i 's/-lcurl/-lcurl -lssl -lcrypto -ldl/g' Makefile
sed -i 's/xof/xf/g' templates/Makefile
#sed -i 's/ln "/ln -s "/' Makefile
sed -i 's,ln "$$bindir/$$p",ln -s "$(bindir_SQ)/$$p",' Makefile

#########
# Compile
make V=1 || exit 1

#########
# Install into dir under /var/tmp/install
rm -rf "$DST"
make install DESTDIR=$DST # --with-install-prefix may be an alternative

#########
# Check result
cd $DST
# [ -f usr/bin/myprog ] || exit 1
# (file usr/bin/myprog | grep -qs "statically linked") || exit 1

#########
# Clean up
cd $DST
strip opt/git/bin/*
strip opt/git/libexec/git-core/*

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
