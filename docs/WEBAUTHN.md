# WebAuthn verifier reference

passkit implements the verifier-side (Relying Party) checks of the W3C WebAuthn
Level 2 registration and assertion ceremonies. This page lists the checks
performed, in order, and maps each to its rejection code.

## Registration — `verify_registration`

Inputs: `attestation_object`, `client_data_json`, `expected_challenge`,
`expected_origins`, `rp_id`, `require_user_verification`.

| # | Check | Rejection code |
| - | ----- | -------------- |
| 1 | `clientData.type == "webauthn.create"` | `bad_type` |
| 2 | `clientData.challenge` equals expected (constant-time) | `challenge_mismatch` |
| 3 | `clientData.origin` in `expected_origins` (normalized) | `origin_mismatch` |
| 4 | attestation object parses (CBOR, fmt/attStmt/authData) | `bad_cbor` / `bad_structure` |
| 5 | `authData.rpIdHash == SHA-256(rp_id)` | `rpid_mismatch` |
| 6 | UP flag set | `up_missing` |
| 7 | UV flag set (if required) | `uv_required` |
| 8 | attested credential data present | `no_attested_data` |
| 9 | credential public key parses as a supported COSE key | `COSEError` |

Returns `RegistrationResult` with `credential_id`, `credential_public_key`
(store this), `sign_count`, `aaguid`, and flag booleans.

## Assertion — `verify_assertion`

Inputs: `credential_public_key` (from registration), `authenticator_data`,
`client_data_json`, `signature`, `expected_challenge`, `expected_origins`,
`rp_id`, `stored_sign_count`, `require_user_verification`, and optional
`credential_id` / `expected_credential_id`.

| # | Check | Rejection code |
| - | ----- | -------------- |
| 0 | selected credentialId matches (if both provided) | `cred_mismatch` |
| 1 | `clientData.type == "webauthn.get"` | `bad_type` |
| 2 | challenge binding (constant-time) | `challenge_mismatch` |
| 3 | origin binding | `origin_mismatch` |
| 4 | `rpIdHash == SHA-256(rp_id)` | `rpid_mismatch` |
| 5 | UP flag set | `up_missing` |
| 6 | UV flag set (if required) | `uv_required` |
| 7 | signature verifies over `authData ‖ SHA-256(clientDataJSON)` | `bad_signature` |
| 8 | `signCount` monotonicity | *warning* (`clone_warning`), not a hard fail |

Returns `AssertionResult` with `new_sign_count` (persist it),
`clone_warning`, `warnings`, and flag booleans.

### The signed message

For an assertion the authenticator signs:

```
message = authenticatorData || SHA-256(clientDataJSON)
```

passkit reconstructs exactly this and verifies it with the stored COSE key
(ECDSA-P256/SHA-256 for ES256, RSASSA-PKCS1-v1_5/SHA-256 for RS256).

## Supported algorithms

| COSE alg | Name | Key | Verify |
| -------- | ---- | --- | ------ |
| -7 | ES256 | EC P-256 | ECDSA(SHA-256), DER signature |
| -257 | RS256 | RSA ≥ 2048 | PKCS#1 v1.5(SHA-256) |

Other algorithms are rejected at key-parse time.

## Origin normalization

Origins are normalized to `scheme://host[:port]` with scheme+host lowercased
and default ports (443/80) folded, so `https://x.mil` and `https://x.mil:443`
compare equal. Anything without a scheme+host is rejected.
