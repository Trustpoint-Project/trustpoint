# Operations and Maintenance

This document describes operational procedures, monitoring, logging, health checks, backup strategies, and troubleshooting guidance for running Trustpoint in production.

## Monitoring

### Prometheus Metrics

**Metrics endpoint:** `/metrics`

**Key metrics categories:**

| Category | Key Metrics | Description |
|---|---|---|
| **HTTP** | `django_http_requests_total_by_method_total`<br/>`django_http_requests_latency_seconds`<br/>`django_http_responses_total_by_status_total` | Request count, latency quantiles, response status codes |
| **Database** | `django_db_query_duration_seconds`<br/>`django_db_connections_total` | Query performance, connection pool usage |
| **Workflows** | `workflows2_jobs_queued`<br/>`workflows2_jobs_running`<br/>`workflows2_jobs_completed_total`<br/>`workflows2_jobs_failed_total` | Job queue depth, execution status, worker health |
| **Certificates** | `trustpoint_certificates_issued_total`<br/>`trustpoint_certificates_expiring_soon`<br/>`trustpoint_certificates_revoked_total`<br/>`trustpoint_devices_registered_total` | Certificate lifecycle metrics, device inventory |

**Integration:** Use Prometheus to scrape `/metrics`, visualize with Grafana dashboards.

---

## Logging

### Log Locations

| Log Type | Location | Rotation | Retention |
|---|---|---|---|
| **Application** | `/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log` | Daily or 100MB | 30 days |
| **NGINX Access** | `/var/log/nginx/access.log` | Daily | Configurable |
| **NGINX Error** | `/var/log/nginx/error.log` | Daily | Configurable |
| **PostgreSQL** | `/var/lib/postgresql/data/log/` | Daily | Configurable |
| **Worker** | Same as application | Daily or 100MB | 30 days |

---

## Capacity Planning

### Resource Requirements

| Deployment Size | CPU | RAM | Disk | Notes |
|---|---|---|---|---|
| **Small** (<1,000 devices) | 2 cores | 4 GB | 20 GB | Single instance |
| **Medium** (1,000-10,000 devices) | 4 cores | 8 GB | 100 GB | Single instance |
| **Large** (>10,000 devices) | 8+ cores | 16+ GB | 500+ GB | Multi-instance, DB replication |

### Scaling Guidelines

**Horizontal scaling:**
- Add web instances behind load balancer for increased request capacity
- Add worker instances for parallel job processing
- Use PostgreSQL read replicas for reporting queries

**Vertical scaling:**
- Increase database CPU/memory for query performance
- Increase Gunicorn worker count per instance
- Expand disk for certificate and log storage

**Storage planning:**
- 100-500 bytes per certificate record
- 10-50 KB per device (with history)
- 1-10 GB/month for logs (varies by activity)

### Performance Targets

| Metric | Target | Notes |
|---|---|---|
| **Web UI response time** | <500ms p95 | Page load time |
| **API response time** | <200ms p95 | REST API endpoints |
| **Certificate issuance** | <5 seconds | End-to-end enrollment |
| **API throughput** | 100-1,000 req/s | Depends on instance count |
| **Uptime (standard)** | 99.9% | 8.7 hours downtime/year |

---

## Best Practices

1. **Monitor proactively** - Set up alerts for key metrics (queue depth, error rate, expiring certificates)
2. **Automate backups** - Daily encrypted backups to offsite storage, test recovery quarterly
3. **Use hardware HSM** - Protect CA keys in production environments
4. **Enable audit logging** - Forward to SIEM for security monitoring and compliance
5. **Plan capacity** - Monitor growth trends, scale before hitting limits
6. **Test disaster recovery** - Practice recovery procedures annually
7. **Keep software updated** - Apply security patches within 30 days
8. **Document procedures** - Maintain runbooks for common operations
9. **Use configuration management** - Version control all configuration files
10. **Implement monitoring redundancy** - Don't rely solely on Trustpoint's own monitoring
