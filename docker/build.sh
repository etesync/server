#! /bin/bash

# Build the `test-server` image, which runs the server in a simple configuration
# designed to be used in tests, based on the current git revision.

TAG="${1:-latest}"

echo "Building working copy to etesync/test-server:${TAG}"

ETESYNC_VERSION=$(git describe --tags)

docker build \
    --build-arg ETESYNC_VERSION=${ETESYNC_VERSION} \
    -t etesync/test-server:${TAG} \
    -f docker/test-server/Dockerfile \
    .
