# Research: Features — Production IDS Requirements

## Table Stakes (Snort 3, Suricata, Wazuh baseline)
1. Real-time packet capture & filtering
2. Rule engine (YAML-based, Suricata-compatible subset)
3. Signature & anomaly-based hybrid detection
4. Structured logging (JSON) + syslog export
5. Performance stats (packet drop rate, detection latency, CPU/memory)
6. Persistence (blocklist, alert history, ML model checkpoints)
7. Multi-platform (Windows netsh, Linux iptables/nftables)
8. Configuration hot-reload (no restart on rule updates)

## User Expectations
- **Minimal false positives** — tuned thresholds, whitelist management
- **Explainability** — show features that triggered each alert
- **Performance transparency** — detection engine can't block normal traffic
- **Alert deduplication** — don't spam same alert 1000x/sec
- **Customizable actions** — log-only vs. active blocking per rule

## NetGuard Differentiators (vs. Snort/Suricata)
1. **Lightweight, Python-native** — embeddable, not standalone daemon
2. **ML-first** — anomaly detection primary, rules secondary
3. **Simple YAML rules** — not Snort syntax complexity
4. **Zero-touch deployment** — sensible defaults, works out-of-box
5. **Rich GUI** — real-time traffic visualization, not CLI-only
6. **Cross-platform firewall abstraction** — unified API for Windows/Linux

## Anti-Features (Explicitly OUT of Scope)
- ❌ Deep Packet Inspection as default — optional plugin only (privacy + complexity)
- ❌ Advanced threat hunting — defer to Wazuh/ELK
- ❌ Clustering & distributed deployment — single-machine target
- ❌ Custom protocol dissection — known protocols via Scapy only
- ❌ ML on encrypted traffic — impossible; focus on flow metadata

## Performance Expectations
| Mode | Throughput | Context |
|------|-----------|---------|
| Pure Python IDS | ~10-50k pps | CPU-bound, GIL limitation |
| Optimized (Numba, multiprocessing) | ~100k pps | Multi-core utilization |
| C-based (Suricata) | ~1M+ pps | Not our target |
- Position NetGuard for embedded/SDN/host-based use cases
- Document performance limits clearly in README

## Documentation Deliverables
1. Architecture README with diagrams
2. Configuration guide with examples
3. Rule writing tutorial with 10 example rules
4. Troubleshooting guide for common errors
5. Contribution guide + security policy

---
*Research date: 2026-03-11*
