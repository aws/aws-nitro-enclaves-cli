#!/bin/bash

apt-get update

# Install rust toolchain and its dependencies
apt-get install -y curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
echo "source $HOME/.cargo/env" >> $HOME/.bashrc

# Install dependencies to be able to use musl target to produce statically
# linked binaries.
apt-get install -y gcc libssl-dev
apt-get install -y pkg-config
apt-get install -y musl-tools

# Build static version of Openssl.
apt-get install -y wget unzip
export OPENSSL_VERSION=OpenSSL_1_1_1d
mkdir /openssl_src
wget https://github.com/openssl/openssl/archive/${OPENSSL_VERSION}.zip -P /openssl_src
unzip /openssl_src/${OPENSSL_VERSION}.zip -d /openssl_src
cd /openssl_src/openssl-${OPENSSL_VERSION} && CC=musl-gcc CFLAGS=-fPIC ./Configure --prefix=/musl_openssl --openssldir=/musl_openssl no-shared no-engine -no-afalgeng linux-x86_64 -DOPENSSL_NO_SECURE_MEMORY && make && make install

# Setup the right rust ver
export RUST_VERSION=1.38.0
source $HOME/.cargo/env && rustup toolchain install ${RUST_VERSION}-x86_64-unknown-linux-gnu
source $HOME/.cargo/env && rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu
source $HOME/.cargo/env && rustup target add --toolchain ${RUST_VERSION} x86_64-unknown-linux-musl

# Install cargo-fuzz
cargo install cargo-fuzz

apt-get install -y jq
