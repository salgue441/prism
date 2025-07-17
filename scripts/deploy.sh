#!/bin/bash

set -e

echo "🚀 Deploying API Gateway"
echo "========================"

# Configuration
ENVIRONMENT=${1:-development}
CONFIG_FILE="configs/docker-config.json"

case $ENVIRONMENT in
    "development"|"dev")
        echo "Deploying to development environment..."
        docker-compose up -d
        ;;
    "production"|"prod")
        echo "Deploying to production environment..."
        if [ ! -f "docker-compose.prod.yml" ]; then
            echo "❌ Production config not found!"
            exit 1
        fi
        docker-compose -f docker-compose.prod.yml up -d
        ;;
    "kubernetes"|"k8s")
        echo "Deploying to Kubernetes..."
        if [ ! -d "deployments/kubernetes" ]; then
            echo "❌ Kubernetes manifests not found!"
            exit 1
        fi
        kubectl apply -f deployments/kubernetes/
        ;;
    *)
        echo "❌ Unknown environment: $ENVIRONMENT"
        echo "Usage: $0 [development|production|kubernetes]"
        exit 1
        ;;
esac

echo ""
echo "✅ Deployment completed!"
echo ""
echo "Health check:"
echo "  curl http://localhost:8080/health"
echo ""
echo "Load balancing test:"
echo "  for i in {1..6}; do curl http://localhost:8080/api/users; echo; done"