#!/bin/bash

if [ ! -f "$1" ]; then
	echo "Invalid file passed. Please pass a valid file"
	exit
fi

openssl dgst -sha1 -sign privatekey.pem $1 | base64