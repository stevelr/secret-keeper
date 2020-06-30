#!/bin/sh

# This script tests the encrypt program by encrypting and decrypting a file.
# If no file is provided on the command line, "/etc/services" is used.
#
# There are three encrypt/decrypt passes, to test each of three secret-keepers.
# 1. environment variable
# 2. hashicorp vault
# 3. prompt
# 4. google cloud kms
#
# Before running hashicorp vault, the vault needs to be running
#    at http://127.0.0.1:8200 (or $VAULT_ADDR)
# and a valid token needs to be set in $VAULT_TOKEN
# If you set up vault with the instructions in 
#    secret-keeper/examples/hashivault/README.md
# then these variables are set in 
#

# first arg is file name to encrypt, or default will be "/etc/services"
TEST_FILE=${1:-/etc/services}

[ -n "$TEST_FILE" ] && [ ! -f "$TEST_FILE" ] && echo File "$TEST_FILE" not found. && exit 2
[ -z "$TEST_FILE" ] && echo Please provide file name for encryption && exit 1

PROG=../../target/debug/encrypt

# stop on any error
set -e

test_keeper() {
	local FILE=$1
	local KEEPER_URI=$2
    local tmp_enc="$(mktemp)_enc"
    local tmp_dec="$(mktemp)_dec"
    $PROG enc -k "$KEEPER_URI" -o $tmp_enc $FILE \
     && $PROG dec -k "$KEEPER_URI" -o $tmp_dec $tmp_enc \
     && cmp $FILE $tmp_dec \
     && echo success! \
     && ls -l $FILE $tmp_enc $tmp_dec
}


echo Encrypt/Decrypt using key derived from environment variable
export VAULT_PASSWORD="a random phrase";
test_keeper $TEST_FILE "env:"

echo Encrypt/Decrypt using key stored in hashivault
source ../../keepers/hashivault/examples/secret.env
test_keeper $TEST_FILE hashivault://my-secret-key

# promptKeeper - commented out so this can run w/o interaction
#echo Encrypt/Decrypt using key derived from prompt
#test_keeper $TEST_FILE "prompt:"

echo Encrypt/Decrypt using CloudKMS key
test_keeper $TEST_FILE "cloudkms:/pasillanet/global/my_keyring/my_key"
