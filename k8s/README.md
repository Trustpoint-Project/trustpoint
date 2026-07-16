# Kubernetes Deployment for Trustpoint

This ### 6. Deploy Trustpoint Application
```bash
kubectl apply -f trustpoint-deployment.yaml
kubectl apply -f trustpoint-service.yaml
```

### 7. Deploy Trustpoint Workerry contains Kubernetes manifests for deploying Trustpoint in a Kubernetes cluster.

## Architecture

- **trustpoint**: Main application deployment with HTTPS service
- **trustpoint-worker**: Background worker deployment
- **postgres**: PostgreSQL database (StatefulSet)

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl configured
- Sufficient storage for PersistentVolumes

## Quick Start

### 1. Create Namespace
```bash
kubectl apply -f namespace.yaml
```

### 2. Create Secrets
```bash
# Edit secrets with your actual values
kubectl apply -f secrets.yaml
```

### 3. Create ConfigMaps
```bash
kubectl apply -f configmap.yaml
```

### 4. Create Persistent Volumes
```bash
kubectl apply -f persistent-volumes.yaml
```

### 5. Deploy Database
```bash
kubectl apply -f postgres-statefulset.yaml
kubectl apply -f postgres-service.yaml
```

### 6. Deploy Trustpoint Application
```bash
kubectl apply -f trustpoint-deployment.yaml
kubectl apply -f trustpoint-service.yaml
```

### 7. Deploy Trustpoint Worker
```bash
kubectl apply -f trustpoint-worker-deployment.yaml
```

### 8. Configure Ingress (optional)
```bash
# Edit ingress.yaml with your domain
kubectl apply -f ingress.yaml
```

## Deploy All at Once
```bash
kubectl apply -f namespace.yaml
kubectl apply -f secrets.yaml
kubectl apply -f configmap.yaml
kubectl apply -f persistent-volumes.yaml
kubectl apply -f .
```

## Verification

```bash
# Check pods
kubectl get pods -n trustpoint

# Check services
kubectl get svc -n trustpoint

# Check logs
kubectl logs -n trustpoint -l app=trustpoint
```

## Accessing Trustpoint

### Via LoadBalancer
```bash
kubectl get svc trustpoint -n trustpoint
# Access via EXTERNAL-IP
```

### Via Ingress
Configure your DNS to point to the Ingress controller's IP.

## Customization

- **Resources**: Adjust resource limits in deployment files
- **Replicas**: Scale trustpoint pods in `trustpoint-deployment.yaml`
- **Storage**: Modify PVC sizes in `persistent-volumes.yaml`
- **Environment**: Update values in `configmap.yaml` and `secrets.yaml`

## Security Notes

- Always use strong passwords in production
- Restrict access to secrets
- Enable RBAC and network policies
- Use proper TLS certificates for ingress
- Consider using external secrets management (Vault, AWS Secrets Manager, etc.)

## Troubleshooting

```bash
# Describe pod
kubectl describe pod -n trustpoint <pod-name>

# View logs
kubectl logs -n trustpoint <pod-name>

# Shell into pod
kubectl exec -it -n trustpoint <pod-name> -- /bin/bash

# Check database connectivity
kubectl exec -it -n trustpoint <trustpoint-pod> -- curl http://postgres:5432
```
