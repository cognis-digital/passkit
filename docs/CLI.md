# CLI reference

```
passkit <command> [options]
```

All ceremony inputs are JSON with **base64url-encoded** byte fields, so the CLI
works over files and pipes and suits air-gapped workflows. Read from a file
argument or stdin (`-`).

## `passkit challenge`

Issue a single-use challenge.

```bash
passkit challenge --ttl 120
```

Output:
```json
{ "id": "...", "challenge_b64url": "...", "expires_at": 1750000000, "ttl_seconds": 120 }
```

## `passkit verify-registration`

Input JSON:
```json
{
  "attestationObject": "<base64url>",
  "clientDataJSON": "<base64url>",
  "expectedChallenge": "<base64url>",
  "expectedOrigins": ["https://login.example.mil"],
  "rpId": "login.example.mil",
  "requireUserVerification": true
}
```
Output on success (exit 0):
```json
{ "ok": true, "credentialId": "...", "credentialPublicKey": "<base64url>",
  "signCount": 0, "aaguid": "...", "userVerified": true, "fmt": "packed" }
```
On failure exit 2 with `{ "ok": false, "code": "...", "error": "..." }`.

## `passkit verify-assertion`

Input JSON:
```json
{
  "credentialPublicKey": "<base64url from registration>",
  "authenticatorData": "<base64url>",
  "clientDataJSON": "<base64url>",
  "signature": "<base64url>",
  "expectedChallenge": "<base64url>",
  "expectedOrigins": ["https://login.example.mil"],
  "rpId": "login.example.mil",
  "storedSignCount": 5,
  "requireUserVerification": true
}
```
Exit codes: `0` verified, `2` verification error, `3` verified **with clone
warning**.

## `passkit score`

Input JSON (an event's signals):
```json
{
  "userPresent": true, "userVerified": true, "hardwareBacked": true,
  "phishingResistant": true, "signCountOk": true, "signCountObserved": true,
  "freshnessSeconds": 3, "maxFreshnessSeconds": 300
}
```
`--json` emits the structured breakdown; default is human-readable text.

## `passkit policy-check`

```bash
passkit policy-check --policy examples/policy_fedgov_aal3.yaml event.json
```
Event JSON:
```json
{
  "phishingResistant": true, "userVerified": true,
  "origin": "https://login.example.mil",
  "aaguid": "ee882879721c491397753dfcce97072a",
  "attestationFormat": "packed", "hardwareBacked": true,
  "signals": { "userPresent": true, "phishingResistant": true, "userVerified": true,
               "hardwareBacked": true, "signCountObserved": true, "freshnessSeconds": 2 }
}
```
If `signals` is present the assurance score is computed and applied to the
policy's `min_assurance` / `min_aal`. Exit `0` allow, `1` deny.

## `passkit report`

Render a self-contained HTML assurance report.

```bash
passkit report event.json -o report.html
```
Input JSON may be either a bare signals object or `{ "signals": {...},
"subject": "...", "rpId": "...", "origin": "..." }`.
