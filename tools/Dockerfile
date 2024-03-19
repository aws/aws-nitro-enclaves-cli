FROM public.ecr.aws/ubuntu/ubuntu:20.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive

# Install rust toolchain and its dependencies
RUN apt-get update && \
	apt-get install -y curl unzip jq make
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "source $HOME/.cargo/env" >> $HOME/.bashrc

# Install dependencies to be able to use musl target to produce statically
# linked binaries.
RUN apt-get update && \
	apt-get install -y gcc libssl-dev pkg-config musl-tools

# Install bindgen dependencies
RUN apt-get update && \
	apt-get install -y llvm-dev libclang-dev clang

# Build static version of Openssl.
ENV OPENSSL_VERSION=OpenSSL_1_1_1q
RUN mkdir /tmp/openssl_src
RUN curl -L https://github.com/openssl/openssl/archive/${OPENSSL_VERSION}.zip -o /tmp/openssl_src/openssl.zip
RUN unzip /tmp/openssl_src/openssl.zip -d /tmp/openssl_src
RUN cd /tmp/openssl_src/openssl-${OPENSSL_VERSION} &&  \
	CC=musl-gcc CFLAGS=-fPIC ./Configure --prefix=/musl_openssl --openssldir=/musl_openssl no-shared no-engine no-afalgeng linux-$(uname -m) -DOPENSSL_NO_SECURE_MEMORY no-tests && \
	make -j$(nproc) && \
	make install_sw

# Setup the right rust ver
ENV RUST_VERSION=1.68.2
RUN  source $HOME/.cargo/env && \
	ARCH=$(uname -m) && \
	rustup toolchain install ${RUST_VERSION}-${ARCH}-unknown-linux-gnu && \
	rustup default ${RUST_VERSION}-${ARCH}-unknown-linux-gnu && \
	rustup target add --toolchain ${RUST_VERSION} ${ARCH}-unknown-linux-musl && \
	cargo install cargo-audit --version 0.17.6 --locked &&  \
	cargo install cargo-about --version 0.5.6 --locked

# Install docker for nitro-cli build-enclave runs
RUN apt-get update && \
    apt-get -y install apt-transport-https \
        ca-certificates \
        curl \
        gnupg2 \
        software-properties-common && \
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg > /tmp/dkey; apt-key add /tmp/dkey && \
    ARCH=$(uname -m) && \
    if [ ${ARCH} == "x86_64" ] ; then ARCH="amd64"; elif [ ${ARCH} == "aarch64" ] ; then ARCH="arm64" ; fi && \
    add-apt-repository \
        "deb [arch=${ARCH}] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") \
        $(lsb_release -cs) \
        stable" && \
    apt-get -y install docker-ce

# Setup the env for nitro-cli
RUN mkdir -p /var/log/nitro_enclaves

RUN echo "Container build ready to go"
