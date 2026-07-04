## What & why

## Security-relevant behavior change?
<!-- Any change to a verifier check, crypto path, or rejection code MUST include
test vectors proving valid inputs are accepted and tampered/relayed/replayed
inputs are rejected. -->

- [ ] Added/updated positive test vectors
- [ ] Added/updated negative (tamper/relay/replay) test vectors
- [ ] `pytest -q` green on 3.10–3.12
- [ ] `python demos/run_all.py` exits 0
- [ ] Defensive scope only
