# Contributing to passkit

Thanks for helping make open, phishing-resistant auth tooling better.

## Ground rules

- **Correctness first.** Any change to a verifier check or crypto path must come
  with test vectors proving it *accepts valid* and *rejects tampered/relayed/
  replayed* inputs. Add both positive and negative cases.
- **Fail closed.** Reject on ambiguity; raise `VerificationError` with a precise
  `code`.
- **Small dependency surface.** Prefer the standard library. New runtime
  dependencies need a strong justification.
- **Defensive scope only.** passkit does not accept offensive capabilities.

## Development

```bash
python -m venv .venv && . .venv/bin/activate    # or your preferred env
pip install -r requirements-dev.txt
pip install -e .
pytest -q
python demos/run_all.py
```

## Pull requests

- Keep PRs focused; describe the security-relevant behavior change.
- CI must be green on Python 3.10–3.12 and all demos must exit 0.
- Do not add attribution footers to commits.

## Adding a test vector

Use `passkit.testing` to build valid ceremonies and mutate them:

```python
from passkit import testing as T
cred, att, cd = T.build_registration(rp_id, origin, challenge)
ad, cdj, sig = T.build_assertion(cred, rp_id, origin, challenge, sign_count=1)
```

Tamper the bytes to construct negative cases and assert the expected rejection
`code`.
