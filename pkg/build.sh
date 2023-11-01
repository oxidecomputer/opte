#!/bin/bash

export PUBLISHER=helios-dev
export COMMIT_COUNT=`git rev-list --count HEAD`
export REPO=packages/repo

set -e
set -x

./clean.sh

# create the proto area
mkdir -p proto/kernel/drv/amd64
mkdir -p proto/opt/oxide/opte/bin
mkdir -p proto/usr/lib/devfsadm/linkmod
cp ../target/release/opteadm proto/opt/oxide/opte/bin/
cp ../target/x86_64-unknown-unknown/release/xde proto/kernel/drv/amd64/xde
cp ../xde/xde.conf proto/kernel/drv/
cp ../target/i686-unknown-illumos/release/libxde_link.so proto/usr/lib/devfsadm/linkmod/SUNW_xde_link.so

API_VSN=$(./print-api-version.sh)

# create the package
sed -e "s/%PUBLISHER%/$PUBLISHER/g" \
    -e "s/%COMMIT_COUNT%/$COMMIT_COUNT/g" \
    -e "s/%API_VSN%/$API_VSN/g" \
    opte.template.p5m | pkgmogrify -v -O opte.base.p5m

pkgdepend generate -d proto opte.base.p5m > opte.generate.p5m

mkdir -p packages
pkgdepend resolve -d packages -s resolve.p5m opte.generate.p5m

cat opte.base.p5m packages/opte.generate.p5m.resolve.p5m > opte.final.p5m

pkgrepo create $REPO
pkgrepo add-publisher -s $REPO $PUBLISHER

pkgsend publish -d proto -s $REPO opte.final.p5m
pkgrecv -a -d packages/repo/opte-0.$API_VSN.$COMMIT_COUNT.p5p -s $REPO \
	-v -m latest '*'
