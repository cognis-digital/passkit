"""Single-use challenge/nonce store with TTL and replay protection.

The store issues cryptographically-random challenges, tracks them with an
expiry, and *consumes* them exactly once. A second attempt to consume the same
challenge (a replay) is rejected. Expired challenges are rejected and reaped.

The store is backend-pluggable so a deployment can swap the default in-memory
backend for Redis/SQL without changing call sites. The in-memory backend is
thread-safe.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Protocol

from passkit._util import b64url_encode
from passkit.errors import ChallengeError

DEFAULT_TTL_SECONDS = 300
DEFAULT_CHALLENGE_BYTES = 32


@dataclass
class Challenge:
    id: str
    value: bytes  # raw challenge bytes (what the client signs over)
    created_at: float
    expires_at: float
    context: Dict[str, str] = field(default_factory=dict)

    @property
    def value_b64(self) -> str:
        return b64url_encode(self.value)

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at


class NonceBackend(Protocol):
    """Storage backend for issued, not-yet-consumed challenges."""

    def put(self, challenge: Challenge) -> None: ...

    def take(self, challenge_id: str, now: float) -> Optional[Challenge]:
        """Atomically remove and return a live challenge, else None."""

    def purge_expired(self, now: float) -> int: ...

    def __len__(self) -> int: ...


class InMemoryNonceBackend:
    """Thread-safe in-memory backend. Good default; not durable across restart."""

    def __init__(self) -> None:
        self._items: Dict[str, Challenge] = {}
        self._lock = threading.Lock()

    def put(self, challenge: Challenge) -> None:
        with self._lock:
            self._items[challenge.id] = challenge

    def take(self, challenge_id: str, now: float) -> Optional[Challenge]:
        with self._lock:
            ch = self._items.pop(challenge_id, None)
            if ch is None:
                return None
            if ch.is_expired(now):
                return None  # already popped; expired -> treat as gone
            return ch

    def purge_expired(self, now: float) -> int:
        with self._lock:
            expired = [cid for cid, ch in self._items.items() if ch.is_expired(now)]
            for cid in expired:
                del self._items[cid]
            return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class ChallengeStore:
    """Issues and consumes single-use challenges with a TTL."""

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        challenge_bytes: int = DEFAULT_CHALLENGE_BYTES,
        backend: Optional[NonceBackend] = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if challenge_bytes < 16:
            raise ValueError("challenge_bytes must be >= 16 for adequate entropy")
        self.ttl_seconds = ttl_seconds
        self.challenge_bytes = challenge_bytes
        self._backend: NonceBackend = backend or InMemoryNonceBackend()

    def issue(self, context: Optional[Dict[str, str]] = None) -> Challenge:
        """Issue a fresh single-use challenge."""
        now = time.time()
        challenge = Challenge(
            id=secrets.token_urlsafe(16),
            value=secrets.token_bytes(self.challenge_bytes),
            created_at=now,
            expires_at=now + self.ttl_seconds,
            context=dict(context or {}),
        )
        self._backend.put(challenge)
        return challenge

    def consume(self, challenge_id: str) -> Challenge:
        """Consume a challenge exactly once.

        Raises ChallengeError with a specific code:
            replay_or_unknown  - already used, never issued, or reaped
            expired            - present but past its TTL
        """
        now = time.time()
        ch = self._backend.take(challenge_id, now)
        if ch is None:
            raise ChallengeError(
                "challenge unknown, already consumed (replay), or expired",
                "replay_or_unknown",
            )
        if ch.is_expired(now):
            raise ChallengeError("challenge expired", "expired")
        return ch

    def purge_expired(self) -> int:
        """Reap expired challenges; returns count removed."""
        return self._backend.purge_expired(time.time())

    def __len__(self) -> int:
        return len(self._backend)


__all__ = [
    "Challenge",
    "ChallengeStore",
    "NonceBackend",
    "InMemoryNonceBackend",
    "DEFAULT_TTL_SECONDS",
]
