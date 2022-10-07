ARG UBUNTU_VERSION=20.04
ARG DISTRO_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits
ARG BN_LICENSE

FROM ${DISTRO_BASE} as base
ARG LIBRARIES

ENV TZ="America/New_York"

RUN apt-get update && apt-get install -yq tzdata && \
    ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install -yq curl gpg sudo git tar xz-utils unzip lsb-release wget software-properties-common gnupg build-essential python3-venv && \
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to "/usr/local/bin"

ENV PATH=${LIBRARIES}/bin:/root/.cargo/bin:${PATH}

FROM base as build
ARG LIBRARIES
ARG BN_LICENSE

ENV TZ="America/New_York"

COPY . /app

WORKDIR /app

ENV CMAKE_INSTALL_PREFIX=${LIBRARIES}
ENV VIRTUAL_ENV=${LIBRARIES}
ENV BINJA_PATH="${LIBRARIES}/binaryninja"

RUN just install-prereqs && \
    rm -rf deps/cxx-common.tar.xz && \
    rm -rf deps/cmake.tar.gz && \
    rm -rf deps/ghidra.zip && \
    rm -rf deps/binja.zip

RUN git config --global user.email "root@localhost" && \
    git config --global user.name "root" && \
    just install-irene3

FROM base as dist
ARG LIBRARIES
ARG BN_LICENSE

ENV VIRTUAL_ENV=${LIBRARIES}

VOLUME /workspace
WORKDIR /workspace

RUN export BN_LICENSE="${BN_LICENSE}"

COPY --from=build ${LIBRARIES} ${LIBRARIES}

