#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <version>"
	exit 2
fi

VERSION="$1"

SCRIPT_DIR="$(realpath $(dirname $0))"

pushd "$SCRIPT_DIR/.." >/dev/null

# Update all Cargo.toml files
while read -r toml_file; do
	old_version=$(grep '^rust-version = ' $toml_file | tr -d ' "' | cut -d'=' -f2)
	echo "Updating $toml_file from $old_version to $VERSION .."
	sed -i "s/^rust-version = \"$old_version\"/rust-version = \"$VERSION\"/" "$toml_file"
done < <(find -name "Cargo.toml" | sort)

# Update .github/workflows/ci.yml
sed -i "s/rust: \[[0-9]\+\.[0-9]\+, stable, nightly\]/rust: [$VERSION, stable, nightly]/" .github/workflows/ci.yml

# Update SOURCES/aws-nitro-enclaves-cli.spec
sed -i "s/^BuildRequires: rust >= [0-9]\+\.[0-9]\+/BuildRequires: rust >= $VERSION/" SOURCES/aws-nitro-enclaves-cli.spec
sed -i "s/^BuildRequires: cargo >= [0-9]\+\.[0-9]\+/BuildRequires: cargo >= $VERSION/" SOURCES/aws-nitro-enclaves-cli.spec

# Update README.md
sed -i "s|^\[msrv\]: https://img.shields.io/badge/MSRV-[0-9]\+\.[0-9]\+-blue|[msrv]: https://img.shields.io/badge/MSRV-$VERSION-blue|" README.md

# Update tools/Dockerfile
sed -i "s/^ENV RUST_VERSION=[0-9]\+\.[0-9]\+/ENV RUST_VERSION=$VERSION/" tools/Dockerfile

popd >/dev/null

