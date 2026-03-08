# Project Development Plan

## Scope
This plan targets performance, maintainability, and reliability while keeping existing proxy and recon behavior intact.

## Priority Areas
1. `core/interceptor.py` complexity and coupling.
2. `chemistry/origin_server_ip.py` scanner orchestration cost and synchronous bottlenecks.
3. Long-run memory usage from in-memory traffic records.
4. Limited observability for latency, throughput, and retries.
5. Gradual typing debt in legacy modules.

## Delivery Plan

### Milestone 1: Baseline Instrumentation
- Add benchmark harness and budget checks.
- Add CPU/memory profiling scripts for repeatable diagnostics.
- Track p50/p95 latency, success rate, and RPS.

### Milestone 2: Hot Path Decomposition
- Split interceptor path into dedicated components:
  - connection lifecycle
  - HTTP parsing/building
  - retry/advisor flow
  - record sink
- Keep current public API stable.

### Milestone 3: Recon Pipeline Optimization
- Move scanner scheduling to bounded async execution.
- Add per-source timeout policy and cancellation.
- Cache stable lookups (DNS/ASN/CT) with TTL and de-duplication.

### Milestone 4: Memory and Stability
- Keep bounded in-memory records (already added via `record_limit`).
- Add optional file-backed record sink for long sessions.
- Add payload-size guardrails for non-critical processing paths.

### Milestone 5: Quality Hardening
- Increase mypy strict coverage module-by-module.
- Keep 100% line coverage in `core` and `chemistry`.
- Add performance non-regression acceptance criteria in CI.

## Success Metrics
- p95 latency improvement >= 20% under benchmark profile.
- Peak memory reduction >= 30% in long-running sessions.
- Zero functional regressions in existing tests and workflows.
