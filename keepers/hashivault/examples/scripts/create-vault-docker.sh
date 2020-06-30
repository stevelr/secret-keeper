#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR=$DIR/..

export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}

# See the README.md file for an overview and motivation for this script.

# create the dirs that the docker instance will use to store data
mkdir -p $DATA_DIR/volumes/{config,data,logs.policies}
if [ ! -f $DATA_DIR/volumes/config/vault-file.json ]; then
	cp $DIR/../vault-file.json $DATA_DIR/volumes/config/
fi

# start the server in the background
echo starting vault server ..
(cd $DATA_DIR && docker-compose up -d)
# give it time to start
sleep 2

echo retrieving secrets
vault operator init > $DIR/../init-SECRETS.log

echo unseal it
sh $DIR/unseal.sh

echo Extracting root key to secret-root.env
ROOT_TOKEN=$(grep --color=never  "Root Token" $DIR/../init-SECRETS.log  | sed "s/^.*://" | tr -d ' ')
echo "export VAULT_TOKEN=\"$ROOT_TOKEN\"" > $DIR/../secret-root.env

echo You can now run 'scripts/make-app-token.sh'

