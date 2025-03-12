#!/bin/sh
set -ex
docker build -t vv8-postprocessor-builder -f ./build/Dockerfile.builder .
# Change the permissions of the current directory to 777
# Change the permissions of the current working directory to 777
chmod 777 "$(pwd)"
ls -ld "$(pwd)"

# Run the Docker command, using named volumes for build caches.
docker run --rm -u 0 \
  -v "$(pwd)":/visiblev8:Z \
  -v rust_build_cache:/root/.cargo/registry:rw \
  -v go_build_cache:/go/pkg:rw \
  vv8-postprocessor-builder make -C /visiblev8

docker build -t visiblev8/vv8-postprocessors:$(git rev-parse --short HEAD) -t vv8-postprocessors-local -f ./build/Dockerfile.vv8 .
