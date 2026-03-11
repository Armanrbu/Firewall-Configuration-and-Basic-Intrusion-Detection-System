# Docker Deployment

## Quick Start

```bash
# Set your API key
export NETGUARD_API_KEY=your-secret-here

# Start
docker compose up -d

# Check status
docker compose ps
docker compose logs -f netguard
```

## Accessing the API

Once running, the REST API is available at:

- **API base:** `http://localhost:5000`
- **OpenAPI docs:** `http://localhost:5000/docs`
- **WebSocket events:** `ws://localhost:5000/ws/events?api_key=your-secret`

Authenticate with the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-secret" http://localhost:5000/status
```

## Custom Port

```bash
NETGUARD_PORT=8080 docker compose up -d
```

## Persisted Data

| Volume | Content |
|--------|---------|
| `netguard_data` | SQLite database (`firewall_ids.db`) |
| `netguard_logs` | Engine log files |

## Live Rule Editing

The `rules/` directory is mounted read-only into the container.
Edit a rule file on the host, then reload without rebuilding:

```bash
# From the host
python -m cli rules reload
# or via the API
curl -X POST -H "X-API-Key: ..." http://localhost:5000/rules/reload
```

## Building the Image

```bash
docker build -t netguard-ids:latest .
```
