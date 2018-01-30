#!/bin/sh

if [ $# -gt 1 -o $1 == "--help" -o $1 == "help" ]; then
	echo ""
	echo "  USAGE:"
	echo ""
	echo "  # ./make_runnerrpms.sh [VERSION]"
	echo ""
	echo "  Will build the RPMs in current dir by using the HEAD commit ID as default."
	echo ""
	exit
fi

if [ y$1 != y ]; then
	VERSION=$1
else
	VERSION=`git describe --tags --match "v[0-9]*"`
fi

VERSION=`echo $VERSION | sed "s/-/./g"`

TCMURUNNER_TAR=tcmu-runner-$VERSION.tar.gz

#echo $TCMURUNNER_TAR

rpmbuild_path=`pwd`/rpmbuild

echo $rpmbuild_path

# Try to clear the old rpmbuild data.
if [ -e $rpmbuild_path ]; then
	rm -rf $rpmbuild_path/*
fi

mkdir -p $rpmbuild_path/BUILD
mkdir -p $rpmbuild_path/SPECS
mkdir -p $rpmbuild_path/RPMS
mkdir -p $rpmbuild_path/SRPMS
mkdir -p $rpmbuild_path/SOURCES

cp ../tcmu-runner.spec $rpmbuild_path/SPECS/
if [ y$1 == y ]; then
	SPEC=$rpmbuild_path/SPECS/tcmu-runner.spec
	sed -i "s/Version:.*$/Version:       ${VERSION}/" $SPEC
	LINE=`grep -n "define" $SPEC |grep _RC`
	LN=`echo $LINE | awk -F: '{print $1}'`
	sed -i "${LN}d" $SPEC
	sed -i "s/%{?_RC:%{_RC}}/0/g" $SPEC
	sed -i "s/%{?_RC:-%{_RC}}//g" $SPEC
fi


# Generate the source package
OLD=`pwd`
TMPDIR=/tmp/tcmu-runner-build
PKG_NAME=tcmu-runner-$VERSION
mkdir -p $TMPDIR/$PKG_NAME && cd $TMPDIR/$PKG_NAME

if [ -e $OLD/../.git ]; then
	git clone $OLD/../.git $PKG_NAME
else
	cp $OLD/../* $PKG_NAME -r
fi

rm -rf $PKG_NAME/.git*

tar -czvf $rpmbuild_path/SOURCES/$TCMURUNNER_TAR $PKG_NAME 2&> /dev/null
cd $OLD
rm -rf $TMPDIR

# Build the RPMs
rpmbuild --define="_topdir $rpmbuild_path" -ba $rpmbuild_path/SPECS/tcmu-runner.spec




