FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y build-essential gcc make wget

ENV KERNEL_REPO="https://kernel.ubuntu.com/~kernel-ppa/mainline"
ENV KERNEL_VER="v5.4.101"
ENV KERNEL_ARCH="amd64"
ENV KERNEL_HDR="linux-headers-5.4.101-0504101_5.4.101-0504101.202102261049_all.deb"
ENV KERNEL_HDR_GENERIC="linux-headers-5.4.101-0504101-generic_5.4.101-0504101.202102261049_amd64.deb"

RUN wget "$KERNEL_REPO"/"$KERNEL_VER"/"$KERNEL_ARCH"/"$KERNEL_HDR" \
         "$KERNEL_REPO"/"$KERNEL_VER"/"$KERNEL_ARCH"/"$KERNEL_HDR_GENERIC"

RUN apt-get install -y ./"$KERNEL_HDR" ./"$KERNEL_HDR_GENERIC"
