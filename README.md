# passkit

**Open, self-hostable, standards-based phishing-resistant authentication tooling.**

passkit is a verifier-side WebAuthn/FIDO2 toolkit built for **correctness**:
real signature verification, real replay/clone protection, and real origin
binding — the property that makes WebAuthn phishing-resistant. It runs offline,
has a tiny dependency surface, and is fully inspectable and test-covered.

Where closed "phishing-resistant identity" products ask you to trust a black
box, passkit is the open alternative you can read, self-host, air-gap, and
audit — with test vectors that prove it *accepts valid* ceremonies and
*rejects tampered, relayed, and replayed* ones.

[![CI](https://github.com/cognis-digital/passkit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/passkit/actions/workflows/ci.yml)

---

## Why phishing-resistant?

Passwords, OTPs, and push prompts are *relayable*: an attacker on a lookalike
domain (`login.examp1e.mil`) can proxy the ceremony and capture the factor.
WebAuthn defeats this because the authenticator signs the **actual origin** the
browser ran on, bound to a **server-issued single-use challenge**. If the
verifier checks the origin and challenge, a relayed ceremony simply fails.

passkit implements those verifier-side checks — plus attestation evaluation,
device/session assurance scoring, and declarative policy — as clean, testable
Python.

## Features

- **`webauthn`** — a correct WebAuthn/FIDO2 **registration + assertion verifier**:
  parses `clientDataJSON` and `authenticatorData`, checks `rpIdHash`, flags,
  and `signCount`, verifies the assertion signature against the registered
  credential public key, and enforces **challenge + origin binding**.
  Supports **ES256** and **RS256**.
- **`attestation`** — parse + evaluate **packed / none** attestation statements,
  surface **AAGUID** and device metadata, and enforce a policy (allowed
  authenticators / require UV / require resident key).
- **`zerotrust`** — a device/session **posture scorer** binding auth strength to
  signals (UV, hardware-backed key, signCount monotonicity anti-clone check,
  freshness) → a **0–100 assurance score** and an **AAL-style level** (modeled on
  NIST SP 800-63B AAL1/2/3) with an **explainable breakdown**.
- **`challenge`** — secure single-use **challenge/nonce store** (replay
  protection + TTL) and a **QR / deeplink** builder for cross-device flows.
- **`policy`** — declarative auth policy (YAML/JSON): require phishing-resistant
  factor, allowed origins, allowed AAGUIDs, min assurance/AAL → allow/deny with
  reasons.
- **`passkit` CLI** — `challenge`, `verify-registration`, `verify-assertion`,
  `score`, `policy-check`, `report` (self-contained HTML assurance report).

## Install

```bash
pip install -e .
# optional YAML policy support:
pip install -e ".[yaml]"
```

Requires Python 3.10+ and [`cryptography`](https://cryptography.io). The CBOR
and COSE-key handling, the challenge store, scoring, policy, and QR encoder are
all pure standard library.

## Quick start (library)

```python
import os
from passkit.challenge import ChallengeStore
from passkit.webauthn import verify_registration, verify_assertion

store = ChallengeStore()
rp_id, origin = "login.example.mil", "https://login.example.mil"

# 1) Registration — persist result.credential_public_key for this user.
challenge = store.consume(store.issue().id)  # in real life: two requests
reg = verify_registration(
    attestation_object=attestation_object_bytes,
    client_data_json=client_data_json_bytes,
    expected_challenge=challenge.value,
    expected_origins=[origin],
    rp_id=rp_id,
    require_user_verification=True,
)

# 2) Assertion (login) — verify against the stored key.
result = verify_assertion(
    credential_public_key=reg.credential_public_key,
    authenticator_data=authenticator_data_bytes,
    client_data_json=client_data_json_bytes,
    signature=signature_bytes,
    expected_challenge=login_challenge.value,
    expected_origins=[origin],
    rp_id=rp_id,
    stored_sign_count=last_seen_count,
    require_user_verification=True,
)
if result.clone_warning:
    ...  # signCount regressed: possible cloned authenticator
```

A relayed ceremony from a lookalike domain raises
`VerificationError(code="origin_mismatch")`; a stale/replayed challenge raises
`code="challenge_mismatch"`; a tampered signature raises `code="bad_signature"`.

## Quick start (CLI)

```bash
# issue a single-use challenge
passkit challenge --ttl 120

# verify ceremonies (JSON in, JSON out; base64url byte fields)
passkit verify-registration reg.json
passkit verify-assertion assert.json

# score an event and render an HTML assurance report
passkit score event.json
passkit report event.json -o report.html

# evaluate a declarative policy
passkit policy-check --policy examples/policy_fedgov_aal3.yaml event.json
```

See [`docs/CLI.md`](docs/CLI.md) for the JSON input schemas.

## Demos

Ten runnable, self-checking demos (each exits 0 on success):

```bash
python demos/run_all.py
```

They cover: end-to-end registration/assertion, phishing (origin-binding)
rejection, replay protection, clone detection, attestation policy, assurance
scoring, policy evaluation, cross-device QR/deeplink, HTML reporting, and a full
tamper matrix.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite includes **test vectors** built with real ECDSA/RSA keys that prove
the verifier accepts valid ceremonies and rejects tampered, relayed, and
replayed inputs across ES256 and RS256.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map and data flow
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — threats, guarantees, and limits
- [`docs/WEBAUTHN.md`](docs/WEBAUTHN.md) — verifier check-by-check reference
- [`docs/ASSURANCE.md`](docs/ASSURANCE.md) — the scoring model and AAL mapping
- [`docs/CLI.md`](docs/CLI.md) — CLI and JSON schemas

## Scope & posture

passkit is **defensive** security tooling: authentication verification,
attestation evaluation, zero-trust posture, and policy. It contains no
offensive capability. The assurance scorer is a **risk aid** modeled on NIST
SP 800-63B AALs — it is not a formal certification, which also depends on
process controls outside a single authentication event.

## License

Cognis Open Collaboration License (COCL) v1.0. See [`LICENSE`](LICENSE).

Built and maintained by **Cognis Digital LLC**.
