#!/usr/bin/env bash
mkdir -p ./irene-ghidra/src/test/resources/ghidra_dbs
cd ./irene-ghidra/src/test/resources/ghidra_dbs
if [[ -z "$(ls -A ./)" ]]
then    
    if [[ -z "$TOB_AMP_PASSPHRASE" ]]
    then
        echo "Please provide a passhphrase in TOB_AMP_PASSPHRASE"
        exit 1
    fi
    curl -LO http://tob-amp-share.nyc3.digitaloceanspaces.com/ghidra_dbs.tar.gz.gpg
    gpg --no-tty --batch --pinentry-mode loopback --passphrase "$TOB_AMP_PASSPHRASE" -o ghidra_dbs.tar.gz --decrypt ghidra_dbs.tar.gz.gpg
    tar --strip-components=1 -xvf ./ghidra_dbs.tar.gz
fi
