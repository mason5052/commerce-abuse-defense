#!/bin/bash
# Build CAD Docker image and push to private registry.
# Run this on Master 1 (10.1.1.71) where Docker is available.
#
# Usage: ./deploy/build-and-push.sh [tag]
#   tag: Docker tag (default: latest)

set -e

REGISTRY="localhost:30500"
IMAGE="cad"
TAG="${1:-latest}"
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION_TAG="0.3.0-${GIT_COMMIT}"

echo "Building CAD image: ${REGISTRY}/${IMAGE}:${VERSION_TAG}"
docker build \
  -t "${REGISTRY}/${IMAGE}:${VERSION_TAG}" \
  -t "${REGISTRY}/${IMAGE}:${TAG}" \
  .

echo "Pushing to registry..."
docker push "${REGISTRY}/${IMAGE}:${VERSION_TAG}"
docker push "${REGISTRY}/${IMAGE}:${TAG}"

echo "Done. Images pushed:"
echo "  ${REGISTRY}/${IMAGE}:${VERSION_TAG}"
echo "  ${REGISTRY}/${IMAGE}:${TAG}"
