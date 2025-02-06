#!/bin/bash

if [ -z "$1" ]; then
	echo "Usage: $0 <encrypted_file>"
	exit 1
fi

if [[ "$1" =~ ".*\.gpg" ]]; then
	echo "Do not include .gpg extension in encrpted file name '$1'"
	exit 1
fi

if [ -f $1 ]; then
	rm $1
fi

# decrypt file
gpg --batch --output $1 --passphrase gatk2025 --decrypt $1.gpg

version="4.6.1.0"
if [ ! -f gatk-${version}.zip ]; then
	rm -rf gatk-${version}
	wget https://github.com/broadinstitute/gatk/releases/download/${version}/gatk-${version}.zip
fi

if [ ! -d gatk-${version} ]; then
	unzip gatk-${version}.zip
fi

cd gatk-${version}
./gatk ValidateSamFile -I ../$1 -M SUMMARY

# clean up decrypted file
rm $1
