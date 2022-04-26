################################################################
# Builder Image (can also be used as developer's image)
################################################################
FROM ubuntu:focal as bazel_builder

ARG PYTHON_VERSION=3.8

ENV TZ=America/New_York \
    DEBIAN_FRONTEND=noninteractive

#  MAGMA_ROOT is needed by python tests (e.g. freedomfi_one_tests in enodebd)
ENV MAGMA_ROOT=/workspaces/magma

RUN echo "Install general purpose packages" && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apt-transport-https \
        apt-utils \
        # dependencies of FreeDiameter
        bison \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        gcc \
        git \
        gnupg2 \
        g++ \
        # dependency of mobilityd (tests)
        iproute2 \
        # dependency of python services (e.g. magmad)
        iputils-ping \
        flex \
        libconfig-dev \
        # dependency of @sentry_native//:sentry
        libcurl4-openssl-dev \
        # dependencies of oai/mme
        libczmq-dev \
        libgcrypt-dev \
        libgmp3-dev \
        libidn11-dev \
        libsctp1 \
        # dependency of sctpd
        libsctp-dev \
        libssl-dev \
        # dependency of pip systemd
        libsystemd-dev \
        lld \
        # dependency of python services (e.g. magmad)
        net-tools \
        # dependency of python services (e.g. pipelined)
        netbase \
        python${PYTHON_VERSION} \
        python-is-python3 \
        # neded for post install script of libfolly-dev
        sudo \
        # dependency of python services (e.g. magmad)
        systemd \
        unzip \
        # dependency of liagent
        uuid-dev \
        vim \
        wget \
        zip

RUN echo "Install Folly dependencies" && \
    apt-get install -y --no-install-recommends \
    libgoogle-glog-dev \
    libgflags-dev \
    libboost-all-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libiberty-dev && \
    echo "Install libtins and connection tracker dependencies" && \
    apt-get install -y --no-install-recommends \
    libpcap-dev=1.9.1-3 \
    libmnl-dev=1.0.4-2

RUN apt-get -y install --no-install-recommends \
    libtool=2.4.6-14

# setup magma artifactories and install magma dependencies
RUN echo 'deb https://artifactory.magmacore.org/artifactory/debian-test focal-ci main' > /etc/apt/sources.list.d/magma.list && \
    echo "deb https://artifactory.magmacore.org/artifactory/debian-test/ focal-1.7.0 main" > /etc/apt/sources.list.d/magma.list && \
    wget -qO - https://artifactory.magmacore.org:443/artifactory/api/gpg/key/public -O /tmp/public && \
    apt-key add /tmp/public && \
    apt-get update -y && \
    apt-get install -y \
        bcc-tools \
        liblfds710 \
        libfolly-dev \
        oai-asn1c \
        oai-gnutls \
        oai-nettle \
        oai-freediameter

# Install bazel
WORKDIR /usr/sbin
RUN wget --progress=dot:giga https://github.com/bazelbuild/bazelisk/releases/download/v1.10.0/bazelisk-linux-amd64 && \
    chmod +x bazelisk-linux-amd64 && \
    ln -s /usr/sbin/bazelisk-linux-amd64 /usr/sbin/bazel

# Update shared library configuration
RUN ldconfig -v

RUN ln -s /workspaces/magma/bazel/bazelrcs/docker.bazelrc /etc/bazelrc

WORKDIR /workspaces/magma
