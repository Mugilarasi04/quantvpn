# Architecture

## Overview

QuantVPN secures multi-tenant access to quantum cloud platforms (e.g. IBM
Quantum). It combines a classical secure tunnel with an active,
entropy-based hardware security control — the two are designed as one
system, not as a VPN with a monitoring feature bolted on afterward.

## Components

### 1. Tunnel

Wraps tenant job submission and result retrieval traffic between the tenant
and the quantum cloud provider. This is the transport layer QuantVPN
provides on top of the provider's existing API.

### 2. Crypto — PQC handshake

Secures the classical control channel using post-quantum cryptography.
Rationale: quantum-cloud users are, by definition, in a threat model where
"a large-scale quantum computer exists" is not a hypothetical — so the
control channel protecting access to that hardware should not rely on
classical-only public-key crypto that a quantum adversary could eventually
break.

### 3. Entropy Monitor — crosstalk-leakage detection

This is the core security control, not a secondary feature.

**Problem it addresses:** on shared quantum processors, one tenant's
circuit execution can cause measurable crosstalk on physically adjacent
qubits assigned to another tenant. This is a side-channel unique to
multi-tenant quantum hardware — it has no direct classical-cloud analogue,
and existing access-control/VPN tooling does not detect or respond to it.

**Design decision — active, not passive:** the entropy monitor does not
just detect anomalous crosstalk and alert. On detecting a leakage anomaly,
it acts:
- **Throttling or rescheduling** the tenant job responsible for (or
  affected by) the anomalous crosstalk.
- **Rotating session keys** for the affected tenant(s) as a precaution
  against the anomaly being an early signal of a more deliberate attack.

This makes the entropy monitor an enforcement point, not just a detector —
consistent with treating hardware-level leakage as a first-class security
concern rather than an observability nice-to-have.

## Data flow (high level)

```
Tenant
  │  PQC handshake (control channel)
  ▼
Tunnel ──── job submission / result retrieval ────▶ Quantum Cloud Provider
  │                                                         │
  │                                            crosstalk / entropy signal
  │                                                         │
  ◀──────────────── Entropy Monitor observes ───────────────┘
        │
        ├─ anomaly detected → throttle/reschedule tenant job
        └─ anomaly detected → rotate session keys
```

## Status

Architecture defined; implementation starting with tunnel scaffolding.
Crypto and entropy monitor modules are stubbed pending their own design
passes.