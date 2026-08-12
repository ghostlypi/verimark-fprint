#!/bin/bash
# Build the verimark-fprint RPM from a clean checkout of this tree.
#
#   ./packaging/build-rpm.sh          build
#   ./packaging/build-rpm.sh install  build, then dnf install the result
#
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
spec="$repo/packaging/verimark-fprint.spec"
name=$(rpmspec -q --queryformat '%{name}\n' "$spec" | head -1)
version=$(rpmspec -q --queryformat '%{version}\n' "$spec" | head -1)
topdir=$(rpm --eval '%{_topdir}')

mkdir -p "$topdir"/{SOURCES,SPECS}

# Archive from git so build artefacts and local scratch never end up in the
# tarball; fall back to the working tree if this is not a checkout.
tarball="$topdir/SOURCES/$name-$version.tar.gz"
if git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$repo" archive --format=tar.gz \
        --prefix="$name-$version/" -o "$tarball" HEAD
else
    tar czf "$tarball" --transform "s,^\.,$name-$version," \
        --exclude=./build --exclude=./.git -C "$repo" .
fi

cp "$spec" "$topdir/SPECS/"
rpmbuild -bb "$topdir/SPECS/$(basename "$spec")"

rpm=$(find "$topdir/RPMS" -name "$name-$version-*.rpm" -newer "$tarball" | head -1)
echo "built: $rpm"

if [ "${1:-}" = install ]; then
    sudo dnf install -y "$rpm"
fi
