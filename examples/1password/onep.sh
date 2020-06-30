#!/bin/bash

# this script uses the 'op' command-line utility to fetch a private key 
# from the 1password vault.
# Dependencies: 'op' and 'jq'

# If you get prompted to log into your 1password account, the simplest
# way to do it is to source signin.sh and type "op-signin". This will
# keep the current shell logged in for about 30 minutes.
#

NAME=$(basename $0)

usage() {
	echo "Lookup key, set VAULT_PASSWORD, and run program"
	echo "  KEY_NAME should be unambiguous key title or its uuid,"
	echo "  and the item's 'password' field must be non-empty"
	echo "    $NAME KEY_NAME PROG args.."
	echo "Create a key in the vault, prints the uuid of the new key"
	echo "    $NAME -create KEY_NAME"
}

# create a key, returning its uuid
create_item () {
  KEY_NAME="$1"
  KEY_UUID=$(op create item password --title "$KEY_NAME" --generate-password | jq -r ".uuid")
  echo Key created. uuid=$KEY_UUID
}

# find key by name or uuid. If it's ambiguous, 1p will print an error
lookup_key () {
    NAME_OR_UUID="$1"
    op get item "$NAME_OR_UUID" --fields password
}


if [ "$1" = "-create" ]; then
	KEY_NAME="$2"
    [ -z "$KEY_NAME" ] && echo "Missing KEY_NAME" && usage && exit 1
	create_item $KEY_NAME
	exit 0
fi

KEY_NAME="$1"
[ -z "$KEY_NAME" ] && usage && exit 1
shift
[ -z "$1" ] && echo "Missing PROG" && usage && exit 1

export VAULT_PASSWORD=$(lookup_key $KEY_NAME)
exec "$@"

