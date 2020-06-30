#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# this script does additional setup for the vault server:
# - add approle auth method
# - enable transit secrets engine
# - create a new 'secret-keeper' role with permission to
#   create, read, and modify keys in the transit engine.
# After this script completes, a file 'secret.env' is created
# containing the auth token for the secret-keeper approle.

ROLE_NAME="secret-keeper"                  # new approle
ROOT_TOKEN_FILE="$DIR/../secret-root.env"  # existing file with root token
APP_TOKEN_FILE="$DIR/../secret.env"        # file to be created with new app token

export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200/}


# Alternately, you could set VAULT_TOKEN to a valid root token
if [ -f $ROOT_TOKEN_FILE ]; then
  source $ROOT_TOKEN_FILE
elif [ -z "$VAULT_TOKEN" ]; then
  echo Did not find $ROOT_TOKEN_FILE, which is created by create-vault-docker.sh.
  exit 1
fi

# enable AppRole authentication method if not already enabled
if [ -z "$(vault auth list | grep approle)" ]; then
    echo "Enablng approle authentication."
    vault auth enable approle
else
    echo "approle auth already enabled"
fi

# enable the transit secrets engine if not already enabled
if [ -z "$(vault secrets list | grep transit)" ]; then 
    echo "Enablng transit secrets engine"
    vault secrets enable transit
else
    echo "transit secrets engine already enabled"
fi

# define policy that allows secretkeeper to create, read, and modify transit keys
cat > _sk_policy.hcl <<EOF
# grant create-key and read-key permission on transit keys
path  "transit/*"  {
  capabilities = [ "create","read","update","delete","list" ]
}
EOF

# upload the policy
vault policy write "$ROLE_NAME" _sk_policy.hcl

# create role for secret-keeper with an long, renewable TTL
vault write -f auth/approle/role/${ROLE_NAME} \
    token_policies="${ROLE_NAME}" \
    token_ttl=24h \
    token_max_ttl=0 \
    max_ttl=0

# obtain the role_id and secret_id (credentials for the new approle)
vault read auth/approle/role/${ROLE_NAME}/role-id > _sk_role_id
vault write -f auth/approle/role/${ROLE_NAME}/secret-id > _sk_secret_id

# extract role_id and secret_id from values returned
# then login to get a token.
#
# note the space in "secret_id " so we don't get "secret_id_accessor"
ROLE_ID=$(grep "role_id" _sk_role_id | sed s/role_id// | tr -d ' ')
SECRET_ID=$(grep "secret_id " _sk_secret_id | sed s/secret_id// | tr -d ' ')
if [ -n "$ROLE_ID" ] && [ -n "$SECRET_ID" ]; then
	vault write auth/approle/login role_id=$ROLE_ID secret_id=$SECRET_ID > _sk_login
else
	echo There was a problem retrieving role and secret
fi
NEW_TOKEN=$(grep "token " _sk_login | sed s/token// | tr -d ' ')

# clean up files containing intermediate secrets
rm -f _sk*


echo export VAULT_TOKEN=\"$NEW_TOKEN\" > $APP_TOKEN_FILE

echo The secret token has been written to the file $APP_TOKEN_FILE.
echo This can be used to initialize the environmet for apps using secret-keeper.
ls -l $APP_TOKEN_FILE

echo The vault server should be up and running. To run the tests,
echo   source ./$APP_TOKEN_FILE
echo   cargo test hashivault

