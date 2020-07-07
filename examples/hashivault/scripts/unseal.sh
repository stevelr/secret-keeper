#!/usr/bin/env bash

unset VAULT_TOKEN

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECRETS="$DIR/../init-SECRETS.log"

if [ ! -f $SECRETS ]; then
	echo Missing init log $SECRETS
	exit 1
fi

export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}

for num in 1 2 3; do
	key=$(cat $SECRETS | grep "Key $num" | sed 's/^.*://')
	vault operator unseal "$key"
done
