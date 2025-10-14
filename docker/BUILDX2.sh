#!/bin/bash

TAGS=""

while (( $# )); do
  TAGS="$TAGS --tag ghcr.io/thorsten-l/l9g-oidc-info:$1"
  TAGS="$TAGS --tag tludewig/l9g-oidc-info:$1"
  shift
done

BUILDING_TAGS=$(echo $TAGS | tr ' ' "\n")

../private/LOGIN.sh

docker buildx build --progress plain --no-cache \
  --push \
  --platform linux/arm64,linux/amd64 $BUILDING_TAGS .
