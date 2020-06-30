#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/../secret.env

KEY_NAME="$1"
if [ -z "$KEY_NAME" ] || [ "$KEY_NAME" = "-h" ] || [ "$KEY_NAME" = "--help" ]; then
	echo "Please provide key name"
	exit 1
fi

KEY_TYPE="${KEY_TYPE:-aes256-gcm96}"
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}

curl -X POST -L \
	--header "X-Vault-Token: $VAULT_TOKEN" \
	--data "{\"type\":\"$KEY_TYPE\",\"exportable\":true,\"allow_plaintext_backup\":true}" \
	${VAULT_ADDR}v1/transit/keys/$KEY_NAME
