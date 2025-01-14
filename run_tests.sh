#!/bin/bash

SRC_DIR="${SRC_DIR:-"."}"

mkdir -p /tmp/async-hvac

os_name=$(uname | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | tr '[:upper:]' '[:lower:]')
# architecture=""
case $(uname -m) in
    i386)   arch="386" ;;
    i686)   arch="386" ;;
    x86_64) arch="amd64" ;;
    arm64) arch="arm64" ;;
    arm)  arch="arm";;
esac

download_version () {
  url=https://releases.hashicorp.com/vault/${1}/vault_${1}_${os_name}_${arch}.zip
  echo $url
}

for version in 1.16.3 1.17.6 1.18.3; 
    do  url="$(download_version $version)"
        echo $url
        wget $url -O /tmp/async-hvac/vault_${version}.zip
        unzip /tmp/async-hvac/vault_${version}.zip -d /tmp/async-hvac/
        mv /tmp/async-hvac/vault /tmp/async-hvac/vault_${version}
        rm /tmp/async-hvac/LICENSE.txt
    done
ls /tmp/async-hvac
cd $SRC_DIR
tox