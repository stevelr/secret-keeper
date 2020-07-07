#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ -z "$VAULT_TOKEN" ]; then
  if [ -f "$DIR/../secret.env" ]; then source $DIR/../secret.env; else
	  echo "VAULT_TOKEN not defined, and no secret.env"
	  exit 1
  fi
fi

VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}

curl -sS -XLIST -L --silent \
	--header "X-Vault-Token: $VAULT_TOKEN" \
	${VAULT_ADDR}v1/transit/keys \
	| jq ".data"


