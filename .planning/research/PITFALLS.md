# Research: Pitfalls — Common Failure Modes & Mitigations

## Performance

### P1: Python GIL & Packet Drops
- **Problem:** High-speed capture (1M+ pps) blocked by GIL on multi-core
- **Mitigation:** `multiprocessing.Pool()` for capture workers (each process has own GIL). Never use threading for CPU work. Monitor packet loss via sniff() drop counter.

### P2: ML Model Inference Latency
- **Problem:** PyOD model inference blocks packet processing
- **Mitigation:** Batch scoring (10-100 packets). Use LODA for O(1) prediction. GPU acceleration for deep models. Pre-compute offline when possible.
- **Benchmarks:** IForest ~100µs, ECOD ~10µs, DIF ~500µs per prediction

## Security

### S1: Plugin Injection
- **Problem:** User-supplied detection plugins can execute arbitrary code
- **Mitigation:** Run plugins in restricted subprocess with cgroup limits. Require admin approval. Cryptographic signatures (RSA) for plugin verification. Resource limits: cpu_count=1, memory_limit=256MB per plugin.

### S2: Firewall Command Injection
- **Problem:** Malicious IPs in alerts can inject shell commands
- **Mitigation:** Always use `subprocess.run([list, args])` never `os.system(f-string)`. Validate ALL IPs with `ipaddress.ip_address()` before firewall commands. Kernel validates IP format as second defense.

## Architecture

### A1: Cross-Platform Firewall Failures
- **Common failures:**
  - Assuming root/admin always available → graceful degradation
  - IPv6 not handled → validate with ipaddress module
  - Rules don't persist across reboots → explicitly mark persistent
  - Duplicate rules cause errors → check-before-add pattern
- **Mitigation:** Abstract per-platform implementations behind common interface. Test both platforms in CI.

## Machine Learning

### ML1: Model Drift & Accuracy Degradation
- **Problem:** Model trained on old data becomes stale (concept drift)
- **Symptoms:** False positive rate creeps 1% → 5% over months
- **Mitigation:** Retrain daily on last 7 days of benign traffic. Active learning on uncertain predictions (0.4-0.6 score). Track precision/recall/F1 over time. A/B test models.

## Adoption

### AD1: Complexity & Documentation
- **Problem:** Production IDS tools have steep learning curves
- **NetGuard advantage:** YAML rules, auto-tuned ML defaults, GUI-first, example configs for common scenarios
- **Deliverables:** Architecture README, config guide, rule tutorial, troubleshooting guide

### AD2: Performance Expectations Mismatch
- **Problem:** Users expect Suricata-like throughput from Python
- **Reality:** Pure Python ~10-50k pps vs. C-based ~1M+ pps
- **Mitigation:** Document limits clearly. Benchmark on target hardware. Recommend native tools for backbone networks. Position NetGuard for host-based/embedded/SDN use cases.

## Summary Matrix

| Pitfall | Severity | Likelihood | Mitigation Cost |
|---------|----------|------------|----------------|
| GIL packet drops | High | Medium | Medium (multiprocessing) |
| ML inference latency | Medium | High | Low (batching) |
| Plugin injection | Critical | Low | High (sandboxing) |
| Command injection | Critical | Medium | Low (subprocess list) |
| Cross-platform failures | High | High | Medium (abstraction) |
| Model drift | Medium | High | Medium (retraining) |
| Documentation gaps | Medium | High | Medium (writing) |
| Performance mismatch | Low | High | Low (documentation) |

---
*Research date: 2026-03-11*
