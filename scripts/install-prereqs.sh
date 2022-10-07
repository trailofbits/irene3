#!/bin/bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR="$(realpath "${DIR}/..")"

function install_just {
  if [[ "${OSTYPE}" == "darwin"* ]]
  then
    brew install just
  elif [[ ${OSTYPE} == "linux"* ]]
  then
    curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to "${HOME}/.local/bin"
    echo "export PATH=\${HOME}/.local/bin:\${PATH}" >>~/.profile
    export PATH=${HOME}/.local/bin:${PATH}
  else
    exit 1
  fi
}

sudo apt-get update
sudo apt-get install -yq curl gpg sudo git cargo tar xz-utils unzip lsb-release wget software-properties-common gnupg build-essential python3-venv

if ! command -v "just" &>/dev/null
then
  echo "[+] Installing 'just'"
  install_just
else
  echo "[+] 'just' already installed"
fi

echo "[+] Marking gradle.properties as assume-unchanged"
git update-index --assume-unchanged  "${ROOT_DIR}/gradle.properties"

exec /bin/bash

