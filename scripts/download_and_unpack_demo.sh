#!/usr/bin/env bash
mkdir -p ./tests/demo
cd ./tests/demo || exit 1
if [[ -z "$(ls -A ./)" ]]
then
    if [[ -z "$TOB_AMP_PASSPHRASE" ]]
    then
        echo "Please provide a passhphrase in TOB_AMP_PASSPHRASE"
        exit 1
    fi
    curl -LO http://tob-amp-share.nyc3.digitaloceanspaces.com/demo.tar.gz.gpg
    gpg --no-tty --batch --pinentry-mode loopback --passphrase "$TOB_AMP_PASSPHRASE" -o demo.tar.gz --decrypt demo.tar.gz.gpg
    tar --strip-components=2 -xvf ./demo.tar.gz
fi
