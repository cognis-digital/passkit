# Security model

## What passkit defends against

| Threat | Defense in passkit |
| --- | --- |
| **Phishing / real-time relay** (attacker proxies a ceremony from a lookalike domain) | Origin binding: the signed `clientData.origin` must be an allowed RP origin. A relayed ceremony carries the phishing origin and is rejected (`origin_mismatch`). |
| **Challenge replay** (attacker resubmits a captured ceremony) | Single-use challenge store + verifier challenge binding. A consumed or unknown challenge is rejected; a stale challenge fails `challenge_mismatch`. |
| **Wrong-RP confusion** (credential from another RP) | `rpIdHash` must equal `SHA-256(rp_id)` (`rpid_mismatch`). |
| **Forged / tampered assertion** | Signature is verified over `authenticatorData || SHA-256(clientDataJSON)` against the registered public key (`bad_signature`). Any mutation of authData or clientData breaks it. |
| **Cloned authenticator** | `signCount` monotonicity check flags a non-advancing counter (`clone_warning`). |
| **Weak/soft factors passing as strong** | Assurance scoring + policy: require phishing-resistant factor, UV, hardware-backing, min AAL. |
| **Malformed/hostile input** | Strict CBOR (no trailing bytes, no duplicate keys, no indefinite lengths), strict authData length checks, JSON type checks. |

## Guarantees

- **Constant-time comparison** for challenge, rpIdHash, and credential-id
  equality (`hmac.compare_digest`).
- **No private keys** are ever handled by the verifier; only COSE public keys.
- **No network I/O** in the verification path.
- **Algorithm allow-list**: only ES256 and RS256; RSA modulus < 2048 bits is
  rejected; unsupported COSE curves/types are rejected.

## Explicit non-goals / limitations

- **Attestation trust chains.** passkit *parses and classifies* packed/none
  attestation and surfaces AAGUIDs, but it does **not** validate an x5c chain to
  a FIDO MDS root. Chain-to-root trust requires an out-of-band trust store the
  operator supplies; policy accepts an allow-list of AAGUIDs as the practical
  in-band control.
- **`signCount` is a heuristic.** Many modern platform authenticators and synced
  passkeys report a constant `0`. passkit only warns when a counter regresses;
  it never hard-fails on a zero counter (that would break legitimate passkeys).
- **AAL labels are "-like".** The scorer models NIST SP 800-63B intent for a
  single authentication event. Formal AAL conformance also depends on identity
  proofing, session management, and reauthentication controls outside this
  library.
- **QR encoder scope.** The built-in QR encoder targets byte-mode versions 1–10
  at EC level M for auth deeplinks/URLs; it is not a general-purpose QR library.

## Operator responsibilities

- Persist and compare `signCount` per credential across logins.
- Persist `credential_public_key` from registration and pass it to
  `verify_assertion`.
- Bind each challenge to a session/user and consume it exactly once
  (`ChallengeStore` does this in-process; use a shared backend across nodes).
- Configure `expected_origins` to the exact set of legitimate RP origins.
- Supply authoritative authenticator metadata (e.g. FIDO MDS) if you need
  device-trust decisions beyond an AAGUID allow-list.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md).
