# Security policy

passkit is defensive authentication tooling. We take correctness and
vulnerability reports seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than a
public issue. Include:

- affected module(s) and version,
- a minimal reproduction (test vector preferred), and
- the impact you observed.

We aim to acknowledge within a few business days.

## Scope

In scope: any way to make a verifier **accept** a ceremony it should reject
(forged/relayed/replayed/cloned), or to make it **reject** a valid one; any
memory-unsafe or panic-on-input defect in the parsers; and any weakening of the
cryptographic checks.

Out of scope: attestation trust-chain-to-root validation (documented non-goal;
supply your own trust store), and formal NIST 800-63 conformance claims (the
scorer is a documented risk aid).

## Cryptography

passkit relies on [`cryptography`](https://cryptography.io) for signature
verification and never handles private keys. Signature algorithms are
allow-listed (ES256, RS256) and RSA moduli below 2048 bits are rejected.
