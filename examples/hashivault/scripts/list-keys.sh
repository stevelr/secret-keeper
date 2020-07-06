#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/../secret.env

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}

curl -X LIST -L --silent \
	--header "X-Vault-Token: $VAULT_TOKEN" \
	${VAULT_ADDR}v1/transit/keys \
	| jq ".data"


