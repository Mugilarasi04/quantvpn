# QuantVPN

A VPN / access-control layer purpose-built for secure multi-tenant access to
quantum cloud platforms (e.g. IBM Quantum).

## Problem

Quantum cloud platforms let multiple tenants submit jobs to shared quantum
hardware. This shared access creates two distinct risks that conventional
VPNs don't address:

1. **Classical channel risk** — job submission and result retrieval traffic
   between tenant and provider needs to be secure against both classical and
   quantum adversaries, since data intercepted today can be decrypted later
   once large-scale quantum computers exist ("harvest now, decrypt later").
2. **Hardware-level risk** — on shared quantum processors, one tenant's
   circuit execution can leak information to another tenant through
   crosstalk between physically adjacent qubits. This is a side-channel that
   has no equivalent in classical multi-tenant cloud computing, and no
   existing VPN or access-control product accounts for it.

QuantVPN treats both as first-class concerns rather than treating the
hardware-level risk as someone else's problem.

## Architecture

QuantVPN has three components:

- **Tunnel** — wraps tenant job submission and result retrieval traffic,
  providing the secure channel between tenant and quantum cloud provider.
- **Crypto (PQC handshake)** — secures the classical control channel using
  post-quantum cryptography, so the channel itself isn't the weak link.
- **Entropy Monitor** — an entropy-based crosstalk-leakage detector that
  watches for anomalous cross-tenant signal leakage on shared quantum
  hardware. Unlike a passive alerting system, it's designed to act directly
  on detected anomalies — throttling or rescheduling the affected tenant's
  jobs, or rotating session keys — making it an active security control
  rather than a bolt-on monitoring layer.


**Day 1 — initial scaffolding.** Project structure is in place; tunnel,
crypto, and entropy monitor modules are stubs. Active development is
ongoing, with progress committed daily.




quantvpn/
├── src/
│   ├── tunnel/          # core VPN tunnel logic
│   ├── crypto/          # PQC handshake
│   └── entropy_monitor/ # crosstalk-leakage detection
├── tests/
└── docs/
    └── architecture.md  # detailed design decisions
```