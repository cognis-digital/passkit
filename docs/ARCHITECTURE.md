# Architecture

passkit is organized as small, composable modules with a strict layering: the
low-level codecs know nothing about WebAuthn; the verifier composes the codecs;
the higher layers (attestation policy, scoring, policy) consume verifier
outputs.

```
                 +-------------------+
   CLI / report  |  passkit.cli      |  passkit.report (HTML)
                 +---------+---------+
                           |
   +-----------+-----------+-----------+-------------+
   |           |           |           |             |
webauthn   attestation  zerotrust   challenge      policy
   |           |
   +-----+-----+
         |
   +-----+-----------------------+
   |         |                   |
_cose      _cbor              _util  (base64url, ct-compare, origins)
(COSE keys, (RFC 8949 subset  
 sig verify) decode + encode)
```

## Layers

**Codecs (`_cbor`, `_cose`, `_util`)**
- `_cbor` — a strict, dependency-free CBOR decoder + canonical encoder for the
  subset WebAuthn uses. Strictness is deliberate: trailing bytes, duplicate map
  keys, and indefinite lengths are rejected rather than silently accepted.
- `_cose` — maps COSE_Key structures to `cryptography` public keys and verifies
  ES256/RS256 signatures. Rejects unsupported algorithms/curves and RSA moduli
  below 2048 bits.
- `_util` — base64url, constant-time comparison, SHA-256, and origin
  normalization (default-port folding).

**WebAuthn (`webauthn`)**
- `authdata` — parses `authenticatorData` (rpIdHash / flags / signCount /
  attested credential data / extensions).
- `clientdata` — parses and validates `clientDataJSON`.
- `verifier` — `verify_registration` and `verify_assertion`, composing the
  above with the phishing-resistance checks. This is the security core.

**Attestation (`attestation`)**
- `parser` — parses the attestation object and classifies the statement
  (none / self / basic).
- `metadata` — a small offline AAGUID→device table (extensible by the caller).
- `policy` — allow/deny by AAGUID, format, UV, resident-key.

**Zero-trust (`zerotrust`)**
- `scorer` — turns event signals into a 0–100 score and an AAL-like level with
  a per-signal breakdown.

**Challenge (`challenge`)**
- `store` — single-use nonce store with TTL and a pluggable backend.
- `builder` — cross-device payloads (HMAC-tagged), deeplinks, and a
  dependency-free QR SVG encoder.

**Policy (`policy`)**
- `model` — the declarative policy dataclass + decision type.
- `evaluator` — loads YAML/JSON and evaluates an event's facts.

## Data flow (assertion)

1. Server issues a challenge (`challenge.ChallengeStore.issue`).
2. Client performs `navigator.credentials.get`; server receives
   `authenticatorData`, `clientDataJSON`, and `signature`.
3. `verify_assertion`:
   - parse clientData → check `type`, **challenge binding**, **origin binding**
   - parse authenticatorData → check **rpIdHash**, UP/UV flags
   - verify signature over `authenticatorData || SHA-256(clientDataJSON)`
     against the **stored** COSE public key
   - check **signCount** monotonicity (clone detection)
4. Optionally: `zerotrust.score_event` → `policy.evaluate_policy` → allow/deny.

## Design choices

- **Bytes in, structured out.** Verifiers take raw ceremony bytes, so passkit
  works with any transport (HTTP JSON, gRPC, air-gapped file drop) and any web
  framework — or none.
- **Fail closed, with a code.** Every rejection raises `VerificationError` with
  a machine-readable `code` so callers can branch (e.g. treat `origin_mismatch`
  as a phishing signal distinct from `bad_signature`).
- **Air-gap friendly.** No network calls. The AAGUID table is local and
  overridable; trust-chain decisions are left to policy + a caller-supplied
  metadata source.
