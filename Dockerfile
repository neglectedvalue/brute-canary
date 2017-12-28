FROM debian:testing

RUN apt-get update && apt-get install -y \
  gcc \
  clang \
  cmake \
  libgtest-dev \
  libgoogle-glog-dev \
  libboost-all-dev \
  g++ `#Fb folly deps` \
  automake \
  autoconf \
  autoconf-archive \
  libtool \
  libboost-all-dev \
  libevent-dev \
  libdouble-conversion-dev \
  libgoogle-glog-dev \
  libgflags-dev \
  liblz4-dev \
  liblzma-dev \
  libsnappy-dev \
  make \
  zlib1g-dev \
  binutils-dev \
  libjemalloc-dev \
  libssl-dev \
  libiberty-dev

ENV LD_LIBRARY_PATH=/libs
ENV CPLUS_INCLUDE_PATH=/libs/include

WORKDIR /usr/src
ADD . /usr/src

RUN make PROFILE=no RELEASE=yes all

ENTRYPOINT ["/usr/src/src/main"]