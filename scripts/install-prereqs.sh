#!/bin/bash
set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR="$(realpath ${DIR}/..)"

function install_just {
  if [[ "${OSTYPE}" == "darwin"* ]]
  then
    brew install just
  elif [[ ${OSTYPE} == "linux"* ]]
  then
    local key_file="/usr/share/keyrings/prebuilt-mpr-archive-keyring.gpg"
    if [[ ! -f "${key_file}" ]]
    then
      curl -q 'https://proget.makedeb.org/debian-feeds/prebuilt-mpr.pub' | gpg --dearmor | sudo tee "${key_file}" 1> /dev/null
      echo "deb [signed-by=${key_file}] https://proget.makedeb.org prebuilt-mpr $(lsb_release -cs)" | sudo tee /etc/apt/sources.list.d/prebuilt-mpr.list
    fi
    sudo apt-get update && sudo apt-get -qyy install just
  else
    exit 1
  fi
}

if ! command -v "just" &>/dev/null
then
  echo "[+] Installing 'just'"
  install_just
else
  echo "[+] 'just' already installed"
fi

echo "[+] Marking gradle.properties as assume-unchanged"
git update-index --assume-unchanged  ${ROOT_DIR}/gradle.properties
