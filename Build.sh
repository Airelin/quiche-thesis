#!/bin/bash

# Compiling the applications
cargo build --bin quiche-server
cargo build --bin quiche-client
cargo build --bin quiche-data
echo "Built apps"

# Build docker containers
docker build -f "quiche-server-docker/Dockerfile" -t "quiche-server:latest" .
docker build -f "quiche-client-docker/Dockerfile" -t "quiche-client:latest" .
docker build -f "quiche-data-docker/Dockerfile" -t "quiche-data:latest" .

docker save -o "../containers/quiche-server.tar" "quiche-server:latest"
docker save -o "../containers/quiche-client.tar" "quiche-client:latest"
docker save -o "../containers/quiche-data.tar" "quiche-data:latest"
