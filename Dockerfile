ARG UBUNTU_VERSION=22.04
ARG DISTRO_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits

FROM ${DISTRO_BASE} as base
ARG LIBRARIES

ENV TZ="America/New_York"

RUN apt-get update && apt-get install -yq tzdata && \
    ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install -yq curl gpg sudo git tar xz-utils unzip lsb-release wget software-properties-common gnupg build-essential python3-venv python3-pip && \
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to "/usr/local/bin"

ENV PATH=${LIBRARIES}/bin:/root/.cargo/bin:${PATH}

FROM base as build
ARG LIBRARIES

ENV TZ="America/New_York"

COPY justfile /app/justfile

WORKDIR /app

ENV CMAKE_INSTALL_PREFIX=${LIBRARIES}
ENV VIRTUAL_ENV=${LIBRARIES}


RUN pip install poetry

RUN just install-prereqs && \
    rm -rf deps/cxx-common.tar.xz && \
    rm -rf deps/cmake.tar.gz && \
    rm -rf deps/ghidra.zip

COPY . /app

RUN git config --global user.email "root@localhost" && \
    git config --global user.name "root" && \
    just install-irene3 install-patch-assembler

FROM base as dist
ARG LIBRARIES

ENV VIRTUAL_ENV=${LIBRARIES}
RUN apt-get update && apt-get install -yq libmagic1

VOLUME /workspace
WORKDIR /workspace
RUN mkdir -p /app
COPY --from=build ${LIBRARIES} ${LIBRARIES}
COPY --from=build /app/patch_assembler /app/patch_assembler
