#!/bin/sh
set -ex

echo "Hey buddy" 
# Build the builder image
docker build -t vv8-postprocessor-builder -f ./build/Dockerfile.builder .

# Create named volumes (if they don't already exist)
docker volume create rust_build_cache || true
docker volume create go_build_cache || true

# Run the builder with named volumes instead of bind mounts for caches.
docker run --rm -u 0 \
  -v $(pwd):/visiblev8 \
  -v rust_build_cache:/root/.cargo/registry:rw \
  -v go_build_cache:/go/pkg:rw \
  vv8-postprocessor-builder make -C /visiblev8

# Build the final image
docker build -t visiblev8/vv8-postprocessors:$(git rev-parse --short HEAD) -t vv8-postprocessors-local -f ./build/Dockerfile.vv8 .
