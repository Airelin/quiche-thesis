#!/bin/bash

rustlog="error"
sourcefiles=./send_files

if [ -z $1 ]
then
    echo "Usage is: data.sh <content-type> <sending-rate>"
else
    type=$1
    sourcefiles="./${type}"
fi

if [ -z $2 ]
then
    echo "Usage is: data.sh <content-type> <sending-rate>"
else
    rate=$2
    tc qdisc add dev eth0 root handle 1: tbf rate "${rate}" burst 32kbit latency 400ms
fi

if [ -z $3 ]
then
    echo "Usage is: data.sh <content-type> <sending-rate> <server-ip>"
else
    server=$3
fi

# Add sending rate to features.json
starvation_line=$(grep 'Starvation' "${type}/features.json")
grep -v '}' "${type}/features.json" >> "${type}/feature.json"
rm "${type}/features.json"
grep -v 'Starvation' "${type}/feature.json" >> "${type}/features.json"
echo "${starvation_line}," >> "${type}/features.json"
echo "    \"sending-rate\": \"${rate}\"" >> "${type}/features.json"
echo "}" >> "${type}/features.json"
rm "${type}/feature.json"
mv "${type}/features.json" "features.json"

RUST_LOG="$rustlog" ./quiche-data "https://${server}:4433" --no-verify --root "${sourcefiles}/" --method=POST --store-eval "./logs" --cc-algorithm "bbr"
