FROM irene3


RUN mkdir /builds
WORKDIR /builds
RUN curl https://apt.llvm.org/llvm-snapshot.gpg.key -o llvm-snapshot.gpg.key

RUN apt-key add < llvm-snapshot.gpg.key
RUN add-apt-repository 'deb https://apt.llvm.org/focal/ llvm-toolchain-focal-15 main'
RUN apt-get update 
RUN apt-get install -y qemu-user m4 gcc-arm-linux-gnueabihf openjdk-17-jdk-headless clang-15 libc6-dev-armhf-cross

RUN curl https://embed.cs.utah.edu/csmith/csmith-2.3.0.tar.gz -o csmith.tar.gz
RUN mkdir csmith
RUN tar  --strip-components=1 -xvf csmith.tar.gz -C csmith

WORKDIR /builds/csmith
RUN ./configure
RUN make
RUN cp ./src/csmith /opt/

WORKDIR /opt

RUN curl -sSL https://install.python-poetry.org | python3 -

ENV PATH="${PATH}:/root/.local/bin"
RUN apt install -y python3-pip python-is-python3 


ADD ./ /app

WORKDIR /app

RUN just install-ghidra
RUN just install-irene3-ghidra


WORKDIR /app/eval-scripts
RUN pip install .

ENTRYPOINT ["/app/eval-scripts/docker_runner.sh"]

