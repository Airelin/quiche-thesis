#!/bin/bash

if [ -z $1 ]
then
    echo "Usage is: client.sh <server-ip>"
else
    server=$1
fi

rustlog="error"
receivedfiles=./received_files

RUST_LOG="$rustlog" ./quiche-client "https://${server}:1234" --no-verify --dump-responses "$receivedfiles" --store-eval "./logs"