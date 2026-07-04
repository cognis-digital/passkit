"""Demo 3: single-use challenge replay protection.

A captured challenge cannot be reused. The nonce store consumes each challenge
exactly once; a replay attempt is rejected, and expired challenges are reaped.
"""

import time

from passkit.challenge import ChallengeStore
from passkit.errors import ChallengeError


def main() -> int:
    store = ChallengeStore(ttl_seconds=2)

    ch = store.issue(context={"purpose": "login"})
    print(f"[issue] challenge {ch.id} (ttl=2s)")

    first = store.consume(ch.id)
    print(f"[consume] first use OK, purpose={first.context['purpose']}")

    try:
        store.consume(ch.id)
        print("[demo 3] FAIL: replay accepted")
        return 1
    except ChallengeError as exc:
        print(f"[defense] replay REJECTED: code={exc.code}")

    # expiry
    ch2 = store.issue()
    store._backend._items[ch2.id].expires_at = time.time() - 1  # force-expire
    try:
        store.consume(ch2.id)
        print("[demo 3] FAIL: expired challenge accepted")
        return 1
    except ChallengeError as exc:
        print(f"[defense] expired challenge REJECTED: code={exc.code}")

    print("[demo 3] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
