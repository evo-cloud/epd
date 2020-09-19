#!/bin/bash

BASE="${BASH_SOURCE[0]%/*}/.."
PLATFORMS=
TAG="${1:-latest}"

set -e

cd "$BASE"

rm -fr "bin/docker/images"
mkdir -p "bin/docker/images"
docker buildx build \
    --platform "$PLATFORMS" \
    -f scripts/Dockerfile \
    -o "${OUT:-type=local,dest=bin/docker/images}" \
    -t "evocloud/spf:$TAG" \
    "bin/docker/build"
