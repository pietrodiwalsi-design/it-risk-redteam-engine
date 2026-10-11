# Python Architecture Blueprint: IT Risk & Red Teaming Engine

## 1. Executive Overview & System Architecture Philosophy

This technical specification defines the software design, component modularity, and operational safety mechanisms for an enterprise-grade Red Teaming and IT Risk Assessment Engine. Built in Python 3.10+, the system evaluates external attack surfaces (networks, web apps, APIs) and AI/LLM interfaces (prompt injection, context leakage, excessive agency).

### Core Design Principles:
1. **Strict Dual-Check Scope Enforcement:** Automated target verification against `scope.yaml` utilizing both domain matching and real-time DNS resolution prior to initiating any network probe or LLM prompt.
2. **Operational Safety & Control:** Rate limiting, asynchronous request throttling, token/cost caps, and an instant global emergency stop (**Kill Switch**).
3. **Modularity & Extensibility:** Decoupled architecture separating orchestrators, surface scanners, LLM probes, and compliance reporting engines.
4. **Tamper-Evident Auditability:** Cryptographic SHA-256 hash-chaining of all logged operational events into structured JSONL.

---

## 2. High-Level Component Topology

| Component | Module Name | Primary Operational Responsibility |
|---|---|---|
| **Scope Boundary Enforcer** | `ScopeManager` | Parses `scope.yaml`, performs DNS resolution, validates CIDRs and domains, enforces strict target boundaries. |
| **Safety & Throttle Controller** | `SafetyController` | Enforces requests-per-second, manages async timeouts, tracks LLM token budgets, and triggers the emergency kill switch. |
| **External Surface Scanner** | `ExternalSurfaceScanner` | Conducts non-destructive host discovery, TCP port probing, and security header auditing. |
| **LLM Red Team Assessor** | `LLMRedTeamModule` | Automates prompt injection, context leakage, guardrail bypass, and excessive agency evaluations. |
| **Audit & Activity Logger** | `AuditLogger` | Generates immutable, SHA-256 hash-chained JSONL activity logs capturing all sent payloads, metrics, and responses. |
| **Engine Orchestrator** | `EngineOrchestrator` | Coordinates async execution pipeline across defined targets. |

---

## 3. Data Flow & Security Gates

```
Target Input (Domain / IP / URL)
           │
           ▼
┌──────────────────────────────────────────────┐
│ Gate 1: ScopeManager                         │
│ - Domain whitelist/blacklist check           │
│ - DNS resolution check against CIDR blocks   │
└──────────────────────┬───────────────────────┘
                       │ [ALLOW] (or abort if OUT_OF_SCOPE)
                       ▼
┌──────────────────────────────────────────────┐
│ Gate 2: SafetyController                     │
│ - Kill switch status check                   │
│ - Token bucket rate limiter                  │
│ - LLM token budget check                     │
└──────────────────────┬───────────────────────┘
                       │ [PASS] (or raise InterruptedError)
                       ▼
┌──────────────────────────────────────────────┐
│ Execution Modules                            │
│ - ExternalSurfaceScanner / LLMRedTeamModule  │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│ Gate 3: AuditLogger                          │
│ - Hash-chained (SHA-256) JSONL logging       │
│ - Timestamped event recording                │
└──────────────────────────────────────────────┘
```
