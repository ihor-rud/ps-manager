#!/bin/sh
# Builds a release archive in target/dist. Every archive carries what is
# needed to recover passwords without this program: the spec, the test
# vectors and the Python reference implementation.
#
#   scripts/dist.sh [TARGET]   command-line app; TARGET defaults to this machine
#   scripts/dist.sh web        the browser app, a single HTML file
set -eu

cd "$(dirname "$0")/.."
target=${1:-$(rustc -vV | sed -n 's/^host: //p')}
version=$(cargo pkgid --package psm | sed 's/.*@//')

if [ "$target" = web ]; then
    python3 scripts/build-web.py >/dev/null
    mkdir -p target/dist
    cp target/web/psm.html "target/dist/psm-$version.html"
    echo "target/dist/psm-$version.html"
    exit
fi

name="psm-$version-$target"
exe=
case "$target" in *windows*) exe=.exe ;; esac
cargo build --release --locked --package psm --target "$target"
binary="target/$target/release/psm$exe"
"$binary" selftest

stage="target/dist/$name"
rm -rf "$stage"
mkdir -p "$stage/spec" "$stage/reference"
cp "$binary" README.md LICENSE-APACHE LICENSE-MIT "$stage/"
cp spec/SPEC-v1.md spec/vectors-v1.json "$stage/spec/"
cp reference/psm_ref.py "$stage/reference/"

cd target/dist
case "$target" in
    *windows*) archive="$name.zip" && 7z a -tzip "$archive" "$name" >/dev/null ;;
    *) archive="$name.tar.gz" && tar -czf "$archive" "$name" ;;
esac
echo "target/dist/$archive"
