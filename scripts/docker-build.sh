#!/bin/bash

# Docker Buildx build script for MyEncrypt
set -e

# Configuration
IMAGE_NAME="myencrypt"
TAG="${TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
PUSH="${PUSH:-false}"
CACHE_FROM="${CACHE_FROM:-type=gha}"
CACHE_TO="${CACHE_TO:-type=gha,mode=max}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐳 MyEncrypt Docker Buildx Build (with BuildKit Cache Mounts)${NC}"
echo "=================================================================="
echo -e "Image: ${GREEN}${IMAGE_NAME}:${TAG}${NC}"
echo -e "Platforms: ${GREEN}${PLATFORMS}${NC}"
echo -e "Push: ${GREEN}${PUSH}${NC}"
echo -e "BuildKit: ${GREEN}Enabled with cache mounts${NC}"
echo ""

# Check if buildx is available
if ! docker buildx version >/dev/null 2>&1; then
    echo -e "${RED}❌ Docker Buildx is not available${NC}"
    echo "Please install Docker Buildx or use Docker Desktop"
    exit 1
fi

# Enable BuildKit
export DOCKER_BUILDKIT=1

# Create builder if it doesn't exist
BUILDER_NAME="myencrypt-builder"
if ! docker buildx inspect $BUILDER_NAME >/dev/null 2>&1; then
    echo -e "${YELLOW}📦 Creating buildx builder: ${BUILDER_NAME}${NC}"
    docker buildx create --name $BUILDER_NAME --driver docker-container --bootstrap
fi

# Use the builder
echo -e "${YELLOW}🔧 Using buildx builder: ${BUILDER_NAME}${NC}"
docker buildx use $BUILDER_NAME

# Build arguments
BUILD_ARGS=""
if [ "$PUSH" = "true" ]; then
    BUILD_ARGS="--push"
else
    BUILD_ARGS="--load"
fi

# Add cache arguments if specified
if [ -n "$CACHE_FROM" ]; then
    BUILD_ARGS="$BUILD_ARGS --cache-from=$CACHE_FROM"
fi

if [ -n "$CACHE_TO" ]; then
    BUILD_ARGS="$BUILD_ARGS --cache-to=$CACHE_TO"
fi

# Build the image with BuildKit cache mounts
echo -e "${YELLOW}🔨 Building Docker image with BuildKit cache mounts...${NC}"
docker buildx build \
    --platform $PLATFORMS \
    --tag $IMAGE_NAME:$TAG \
    $BUILD_ARGS \
    .

if [ "$PUSH" = "true" ]; then
    echo -e "${GREEN}✅ Image pushed successfully!${NC}"
else
    echo -e "${GREEN}✅ Image built successfully!${NC}"
fi

# Show image info
echo ""
echo -e "${BLUE}📋 Image Information:${NC}"
echo "====================="
if [ "$PUSH" != "true" ]; then
    docker images $IMAGE_NAME:$TAG
fi

echo ""
echo -e "${BLUE}🚀 Usage Examples:${NC}"
echo "=================="
echo "# Run with default settings:"
echo "docker run -p 14000:14000 -v myencrypt_data:/data $IMAGE_NAME:$TAG"
echo ""
echo "# Run with custom domains:"
echo "docker run -p 14000:14000 -v myencrypt_data:/data \\"
echo "  -e MYENCRYPT_ALLOWED_DOMAINS='localhost,*.localhost,myapp.local,*.myapp.local' \\"
echo "  $IMAGE_NAME:$TAG"
echo ""
echo "# Run with Docker Compose:"
echo "docker-compose up -d"
echo ""
echo -e "${BLUE}💡 BuildKit Features Used:${NC}"
echo "=========================="
echo "- Cache mounts for Go modules (/go/pkg/mod/)"
echo "- Bind mounts for source code"
echo "- Multi-platform builds"
echo "- Optimized layer caching"
