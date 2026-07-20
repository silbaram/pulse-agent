# Audit hash-chain scope

`internal/audit` stores ordered `AuditEvent` records whose SHA-256 digest links to the previous event. The daemon validates this local chain before it performs an audited state change, so an unexpected modification, deletion, or reordering stops that change transaction.

This is a local integrity check, not an external authenticity anchor. An attacker with full write access to the local state file can rewrite the records and their digests together, so this MVP does not claim to provide evidence against that attacker. Remote append-only logging, hardware-backed signing, or another external anchor would require separately approved scope.
