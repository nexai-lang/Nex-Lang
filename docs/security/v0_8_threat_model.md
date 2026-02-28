# NEX v0.8.0 Threat Model and Security Invariants

## Scope
This document defines the pre-ship security gate for cryptographic execution evidence in NEX v0.8.0. It covers event-log evidence emission at runtime and evidence verification during replay.

## Assets
- Agent secret keys (`nex_data/keys/agent_<id>.json`): signing authority for evidence.
- Agent public keys and history (`agent_<id>.json`, `agent_<id>.pubhist.jsonl`): verification material.
- Evidence chain fields:
  - `agent_id`
  - `source_hash`
  - `codegen_hash`
  - `policy_hash`
  - `run_hash`
  - `signature`
- Binary log stream (`events.bin`) and derived JSONL output (`events.jsonl`).

## Trust Boundaries
- Live runtime:
  - Trusted to emit canonical event records and sign evidence with local key material.
- Replay verifier:
  - Trusted to verify structure + cryptographic evidence and fail closed.
- Input logs:
  - Treated as attacker-controlled bytes.
  - Any malformed, truncated, reordered, or tampered bytes must cause deterministic verification failure.

## Canonical Evidence Message (Domain Separation + Schema Freeze)
Evidence signatures are computed over a canonical byte message:

`msg = "NEX-EVIDENCE-V1" || agent_id_le || source_hash || codegen_hash || policy_hash || run_hash`

Rules:
- Domain/version tag is exactly ASCII `NEX-EVIDENCE-V1`.
- `agent_id` is little-endian `u32`.
- Hashes are fixed-width 32-byte raw digests (not hex text).
- Concatenation order is fixed and must not vary by platform.

Implementation binding:
- Signing and verification both use the same canonical builder (`src/runtime/identity.rs`, `evidence_message`).

## Security Invariants
- Fail-closed replay:
  - Any evidence parse error, hash mismatch, signature mismatch, or structural violation returns deterministic failure.
  - Success marker (`✅ REPLAY OK`) is emitted only on full verification success.
- Domain separation:
  - Evidence signatures are scoped to `NEX-EVIDENCE-V1` and cannot be reused across other message domains.
- Canonical bytes:
  - Both signer and verifier use identical byte layout for the signed message.
- Replay execution model:
  - Replay validates logs; it does not perform external side-effect syscalls as part of evidence verification.
- Malformed-log robustness:
  - Malformed evidence/log input must return an error path; no uncontrolled panic behavior is acceptable.

## Key Rotation and Compromise Story
- Rotation:
  - On rotation, previous public key is appended to `agent_<id>.pubhist.jsonl`.
  - Replay accepts old logs by checking current key and archived historical keys.
- Compromise response (minimal v0.8.0 policy):
  - Compromised secret key requires immediate rotation.
  - New logs are signed by the new key; old logs remain verifiable via public-key history.
  - Trust revocation policy for historical signatures is governance-controlled and out of scope for this runtime layer.

## Test Gate Mapping
- Deterministic signature verification on valid replay logs.
- Negative replay tests for tampered signature, tampered `run_hash`, and tampered `policy_hash`.
- Fixed Ed25519 vector verification with embedded public key, signature, and message bytes.
