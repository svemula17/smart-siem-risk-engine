# Quick Start Guide - New Features

## 🔐 Updated Authentication

### Default Credentials (Changed)
```
Username: admin
Password: admin123!  (was: admin)

Username: analyst_1
Password: analyst123!

Username: viewer_1
Password: viewer123!
```

### Login Flow
1. Navigate to `/login`
2. Enter username and password
3. Password verified with PBKDF2 hashing
4. Session token created and stored as HTTPOnly cookie
5. Redirects to `/dashboard`

## 🔑 API Key Management

### Create API Key
```bash
curl -X POST http://localhost:8001/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -d '{"name": "my-automation-key"}' \
  -b "session_token=YOUR_TOKEN"
```

Response:
```json
{
  "key": "sk_abcd1234...",
  "secret": "xxxxx...",
  "name": "my-automation-key",
  "created_at": "2024-01-15T10:30:00"
}
```

**Important**: Save the secret immediately - it's only shown once!

### Use API Key
```bash
curl http://localhost:8001/api/v1/alerts \
  -H "Authorization: Bearer sk_abcd1234"
```

### List Your API Keys
```bash
curl http://localhost:8001/api/v1/api-keys \
  -b "session_token=YOUR_TOKEN"
```

### Revoke API Key
```bash
curl -X DELETE http://localhost:8001/api/v1/api-keys/sk_abcd1234 \
  -b "session_token=YOUR_TOKEN"
```

## 📊 Prometheus Metrics

### Export Metrics
```bash
curl http://localhost:8001/metrics/prometheus
```

### Integrate with Prometheus
Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'smartsiem'
    static_configs:
      - targets: ['localhost:8001']
    metrics_path: '/metrics/prometheus'
```

### Key Metrics to Monitor
- `siem_alerts_critical` - Number of critical alerts
- `siem_incidents_open` - Open incidents
- `siem_playbook_executions` - Automation execution count
- `siem_entities_critical` - High-risk entities

## 💾 Backup & Restore

### Create Backup
```bash
curl -X POST http://localhost:8001/api/v1/backup/create \
  -b "session_token=YOUR_TOKEN"
```

Response:
```json
{
  "status": "success",
  "backup_path": "data/backups/smart_siem_20240115_103000.db.gz"
}
```

### List Backups
```bash
curl http://localhost:8001/api/v1/backup/list \
  -b "session_token=YOUR_TOKEN"
```

Response:
```json
{
  "backups": [
    {
      "name": "smart_siem_20240115_103000.db.gz",
      "path": "data/backups/smart_siem_20240115_103000.db.gz",
      "size_mb": 2.5,
      "created_at": "2024-01-15T10:30:00"
    }
  ],
  "count": 1
}
```

### Restore Backup
```bash
curl -X POST http://localhost:8001/api/v1/backup/restore \
  -H "Content-Type: application/json" \
  -d '{"backup_name": "smart_siem_20240115_103000.db.gz"}' \
  -b "session_token=YOUR_TOKEN"
```

### Clean Old Backups
```bash
curl -X POST "http://localhost:8001/api/v1/backup/cleanup?keep_count=10" \
  -b "session_token=YOUR_TOKEN"
```

## 🌍 GeoIP Enrichment

The system automatically caches GeoIP data when processing alerts. To view cached locations:

```sql
SELECT ip_address, country, city, latitude, longitude FROM geoip_cache LIMIT 10;
```

### Risk Scoring by Country
- OFAC sanctioned (KP, IR, SY, CU): 2.0x risk multiplier
- Medium risk (RU, CN): 1.5x risk multiplier
- Default: 1.0x

## 🔍 Alert Enrichment

Alerts are automatically enriched with:
1. **GeoIP data** - Country, city, coordinates
2. **IOC matches** - Known malicious indicators
3. **Reputation** - Blocked, malicious, clean status
4. **Related alerts** - Count of similar alerts from same IP

This happens transparently in the pipeline.

## 🔗 Webhook Signing

When receiving webhooks from external systems, verify the signature:

```python
from app.services.webhook_signing import WebhookSigner

signer = WebhookSigner("your-webhook-secret")
is_valid = signer.verify_signature(
    payload_json=request.body,
    signature=request.headers["X-Webhook-Signature"],
    timestamp=request.headers["X-Webhook-Timestamp"]
)
if not is_valid:
    return {"error": "Invalid signature"}, 401
```

## 📈 Database Migrations

Migrations run automatically on startup. To check current version:

```bash
curl http://localhost:8001/api/v1/health
```

View migration history in SQLite:
```sql
SELECT version, name, applied_at FROM schema_migrations ORDER BY version;
```

## 🛡️ Security Features

### Rate Limiting
- Default: 100 requests per 60 seconds per IP
- Returns 429 status when exceeded
- Configurable in `security.py`

### CSRF Protection
- Tokens generated for sensitive operations
- One-time use tokens
- 1-hour default TTL

### Input Validation
- All IPs validated with `ipaddress` library
- Internal IPs (RFC 1918) identified
- String lengths validated

### Audit Logging
All actions logged:
```sql
SELECT actor, action, target, result, created_at FROM audit_log 
WHERE action = 'login' 
ORDER BY created_at DESC LIMIT 10;
```

## 🐛 Troubleshooting

### Password Not Working
Old passwords won't work with new hashing. Initialize mock users:
```bash
curl -X POST http://localhost:8001/api/v1/auth/init
```

### API Key Not Found
- Verify key hasn't been revoked
- Check for typos in key
- Ensure session is still valid

### Backup Creation Fails
- Check `data/` directory permissions
- Ensure disk space available
- Verify database isn't locked

### Metrics Endpoint Empty
- Wait for alerts to be processed
- Check that metrics are being recorded
- Verify database connectivity

## 🔄 Migration from Old Version

1. **Backup first**:
   ```bash
   curl -X POST http://localhost:8001/api/v1/backup/create
   ```

2. **Update code** to new version

3. **Restart server** - migrations run automatically

4. **Verify** all features working:
   ```bash
   curl http://localhost:8001/metrics/prometheus
   curl http://localhost:8001/metrics/health
   ```

5. **Reset credentials** if needed:
   ```bash
   curl -X POST http://localhost:8001/api/v1/auth/init
   ```

## 📚 Next Steps

- Review `FIXES_AND_FEATURES.md` for detailed documentation
- Check audit logs for security events
- Set up Prometheus scraping for metrics
- Configure automated backups (cron job)
- Test API keys with your automation tools
