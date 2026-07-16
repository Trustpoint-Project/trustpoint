#!/bin/bash

set -e

echo "🏗️  Building Trustpoint from local source..."

# Use Minikube's Docker daemon
eval $(minikube docker-env)

# Build the image
docker build -f docker/trustpoint/Dockerfile -t trustpointproject/trustpoint:local .

echo "📦 Loading image into Kubernetes..."

# Update the image in the deployments
kubectl set image deployment/trustpoint -n trustpoint trustpoint=trustpointproject/trustpoint:local --record
kubectl set image deployment/trustpoint-worker -n trustpoint trustpoint-worker=trustpointproject/trustpoint:local --record

# Set the imagePullPolicy to Never (use local images only)
kubectl patch deployment trustpoint -n trustpoint -p '{"spec":{"template":{"spec":{"containers":[{"name":"trustpoint","imagePullPolicy":"Never"}]}}}}'
kubectl patch deployment trustpoint-worker -n trustpoint -p '{"spec":{"template":{"spec":{"containers":[{"name":"trustpoint-worker","imagePullPolicy":"Never"}]}}}}'

echo "✅ Deployment updated with local image!"
echo "📊 Checking rollout status..."

kubectl rollout status deployment/trustpoint -n trustpoint
kubectl rollout status deployment/trustpoint-worker -n trustpoint

echo "🎉 Done! Your local changes are now deployed."
