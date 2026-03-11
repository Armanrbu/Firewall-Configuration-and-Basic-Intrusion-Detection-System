# Research: Architecture — Production System Design

## Microkernel Event-Driven Architecture

```
┌────────────────────────────────────┐
│     Packet Capture Daemon          │  (core/packet_capture.py)
│  - Scapy/pcap listening            │  (Python subprocess)
│  - IPC queue output                │
└───────────────┬────────────────────┘
                │ (Redis Streams / multiprocessing.Queue)
┌───────────────▼────────────────────┐
│     Detection Engine               │  (core/ids.py)
│  - Rule matcher (YAML)             │  (Synchronous, CPU-bound)
│  - ML pipeline (PyOD)              │  (Batch scoring)
│  - Firewall abstraction            │
└───────────────┬────────────────────┘
                │ (Alerts queue)
┌───────────────▼────────────────────┐
│   FastAPI Management Server        │  (api/server.py + async)
│  - REST endpoints                  │  (WebSocket for real-time)
│  - GUI communication               │
│  - SQLite writes (alerts/blocks)   │
│  - Config hot-reload               │
└────────────────────────────────────┘
```

### Key Principle
Engine never blocks on UI/API. True event-driven: queues between each layer.

## Event Processing Strategy
- **Event-driven via queues** (not polling)
- `multiprocessing.Queue()` for packet capture → detection
- `redis.Stream` for multi-consumer alerts
- `asyncio.Event` for configuration updates
- Avoid polling filesystem/DB in tight loops

## Plugin/Module System

### Detection Interface
```python
class AbstractDetector:
    def fit(self, training_data: np.ndarray) -> None: ...
    def predict(self, flow: Dict) -> Tuple[bool, float]: ...  # (is_anomaly, score)
```

### Plugin Registration
- Via `entry_points` in pyproject.toml
- Dynamic loading at startup via `importlib.metadata`
- Enables A/B testing multiple models in parallel

### Plugin Directory Structure
```
core/detectors/
├── __init__.py
├── base.py          # AbstractDetector ABC
├── isolation_forest.py
├── snort_rules.py
└── custom_regex.py
```

## Cross-Platform Firewall Abstraction

### Pattern: Strategy + Factory
```python
class FirewallCommand(ABC):
    @abstractmethod
    def block_ip(self, ip: str) -> bool: ...

class WindowsFirewall(FirewallCommand): ...
class LinuxIptables(FirewallCommand): ...
class LinuxNftables(FirewallCommand): ...
```

### Platform-Specific Notes
- **Windows:** `netsh advfirewall` (current), WFP API via ctypes (future)
- **Linux:** iptables (current), nftables (preferred for newer kernels)
- Always validate IPs with `ipaddress` module before shell execution
- Use `subprocess.run([...], check=True)` — never `os.system()`

## Database Abstraction

### Pattern: Repository + Configurable Backend
```yaml
database:
  type: "sqlite"      # dev default
  path: "firewall_ids.db"
  # OR for production:
  # type: "postgresql"
  # url: "postgresql://user:pass@host/netguard_ids"
```

### Core Schema (append-only alerts, mutable blocklist)
- alerts: id, timestamp, src_ip, dst_ip, alert_type, ml_score, rule_id, action
- blocklist: ip, added_at, reason, expires_at, status
- SQLAlchemy ORM for backend-agnostic access

## Service Architecture
- Engine runs as daemon/service (headless capable)
- GUI connects via local API or IPC
- CLI connects via same API
- All frontends are interchangeable consumers

---
*Research date: 2026-03-11*
