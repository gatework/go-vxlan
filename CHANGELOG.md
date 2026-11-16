# Changelog

## v0.5.0

- Align Makefile project/quality gates and packaging with net-connector; adopt go-standards v1.1.0.

- Adopt the published net-connector v0.9.0 module path and go-netops v0.4.0.
- Rename shared inventory platform filters, overrides and device-rule destinations to match Connector.
- Share Parser content indexing across NX-OS configuration and runtime output; retain physical source lines and recognize complete empty L2route tables.
- Preserve scoped BGP summary evidence through collection and typed Fabric decoding; reject conflicting summaries, missing capable-peer rows and inconsistent Port-channel identities.
- Extend read-only runtime assessments while preserving transport receipts, typed APIs and change-safety contracts.

## v0.4.0

- Introduce typed fabric evidence, go-netops assessment, baseline and drift rules, and typed gateway/VLAN/ACL changes.
- Adopt go-standards v1.0.2 and preserve parser/workflow behavior through smaller validation and parsing boundaries.
- Pin published Connector v0.7.1, Expect v0.6.0 and go-netops v0.3.0.
- Document public API and plan migration in [the release notes](docs/releases/v0.4.0.md).
