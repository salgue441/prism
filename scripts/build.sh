#!/bin/bash

set -e

echo "🐳 Building API Gateway Docker Image"
echo "===================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Configuration
IMAGE_NAME="api-gateway"
TAG=${1:-latest}
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

# Build the image
echo "Building Docker image: $FULL_IMAGE_NAME"
docker build -t $FULL_IMAGE_NAME .

# Get image size
IMAGE_SIZE=$(docker images $FULL_IMAGE_NAME --format "table {{.Size}}" | tail -n 1)
print_status "Image built successfully! Size: $IMAGE_SIZE"

# Security scan (if trivy is available)
if command -v trivy &> /dev/null; then
    echo ""
    echo "🔍 Running security scan..."
    trivy image $FULL_IMAGE_NAME
else
    print_warning "Trivy not found. Skipping security scan."
fi

# Test the image
echo ""
echo "🧪 Testing the image..."
docker run --rm $FULL_IMAGE_NAME -version

print_status "Build completed successfully!"
echo ""
echo "To run the image:"
echo "  docker run -p 8080:8080 $FULL_IMAGE_NAME"
echo ""
echo "To run with docker-compose:"
echo "  docker-compose up"