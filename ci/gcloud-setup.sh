#!/bin/sh

# This is a helper script to install and activate gcloud on rust docker images
# such as rust:1.44 from https://hub.docker.com/_/rust    
#    expects basic debian system; doesn't work on -slim or -alpine
#
# If you have installed google-cloud-sdk and run 'gcloud auth login',
# you don't need this.
#
# It ...
#     installs google-cloud-sdk and jq
#     activates gcloud and initializes account and default project
#
# GOOGLE_APPLICATION_CREDENTIALS must be defined.
#

# Confirm prerequisites:
# - we are running on a debian system
# - as root
# - GOOGLE_APPLICATION_CREDENTIALS is defined
deb=$(grep -s "^ID=debian$" /etc/os-release)
if [ "$deb" != "ID=debian" ]; then
  echo This setup script is for debian only.
  exit 1
fi
if [ "$(id -u)" != "0" ]; then
  echo Must run as root
  exit 1
fi
if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  echo Must define GOOGLE_APPLICATION_CREDENTIALS
  exit 1
fi

# Install goole cloud if not installed
if [ ! -x /usr/bin/gcloud ]; then
  echo Installing gcloud
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - \
    && apt-get update -y \
    && apt-get install -y google-cloud-sdk jq
fi

# Install jq if not installed
if [ ! -x /usr/bin/jq ]; then
  apt-get update -y \
  && apt-get install -y jq
fi

# Activate google service account and set project
PROJ=$(jq -r ".project_id" $GOOGLE_APPLICATION_CREDENTIALS)
ACCT=$(jq -r ".client_email" $GOOGLE_APPLICATION_CREDENTIALS)

if [ "$(gcloud config get-value account)" = "(unset)" ]; then
  echo Setting gcloud account $ACCT
  gcloud config set account $ACCT --installation
fi
echo Authorizing gcloud cli for $ACCT
gcloud auth activate-service-account --key-file $GOOGLE_APPLICATION_CREDENTIALS
echo Setting gcloud project $PROJ
gcloud config set project $PROJ --installation
