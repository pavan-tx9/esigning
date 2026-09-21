"""Opaque bearer credentials: host API keys (``esk_``) and session tokens (``est_``).

Two rules hold this file together.

*Only a hash is stored.* A token is shown to its owner exactly once, at the moment it is minted;
what reaches the database is ``sha256(token)``. A database dump therefore cannot be replayed
against the API, and nothing in a backup, a log or a support ticket can be turned back into a
credential.

*Comparison is constant time.* Lookup happens on the hash -- never on the secret -- and the final
check is :func:`hmac.compare_digest`, so a caller cannot learn a token by measuring how long a
wrong guess takes.

Both token types carry 256 bits of randomness from :mod:`secrets`, rendered base64url without
padding, so a token is 4 + 43 characters and contains no character that needs escaping anywhere
it might travel.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Final

__all__ = [
    "HOST_KEY_PREFIX",
    "SESSION_TOKEN_PREFIX",
    "TOKEN_ENTROPY_BYTES",
    "TOKEN_LENGTH",
    "hashes_match",
    "mint_token",
    "parse_token",
    "token_sha256",
]

#: Prefix on a host API key. Visible in a config file, which is why it says what it is.
HOST_KEY_PREFIX: Final = "esk_"

#: Prefix on a signing-session token. Never appears in a URL; postMessage and Authorization only.
SESSION_TOKEN_PREFIX: Final = "est_"  # noqa: S105 - a label, not a secret

#: 256 bits. Anything less is not worth storing evidence against.
TOKEN_ENTROPY_BYTES: Final = 32

#: base64url of 32 bytes, unpadded.
_SECRET_CHARS: Final = 43

#: Full length of a token including its four-character prefix.
TOKEN_LENGTH: Final = 4 + _SECRET_CHARS

_SECRET_RE: Final = re.compile(rf"\A[A-Za-z0-9_-]{{{_SECRET_CHARS}}}\Z")
_BEARER_SCHEME_RE: Final = re.compile(r"\Abearer\s+", re.IGNORECASE)

#: A bearer header longer than this is rejected before it is hashed or parsed.
_MAX_BEARER_CHARS: Final = 256


def mint_token(prefix: str) -> str:
    """A fresh token. The only place in the codebase that creates a credential."""
    if prefix not in (HOST_KEY_PREFIX, SESSION_TOKEN_PREFIX):
        raise ValueError("unknown token prefix")
    return prefix + secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)


def token_sha256(token: str) -> bytes:
    """The 32 raw bytes stored for a token. The token itself is never persisted."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def parse_token(bearer: str | None, prefix: str) -> str | None:
    """Validate the shape of a presented credential.

    Returns the bare token, or ``None`` when it is missing, mis-prefixed, the wrong length or
    contains a character no token of ours can contain. Never raises and never logs: the caller
    turns ``None`` into one indistinguishable ``Unauthorized``. An optional ``Bearer`` scheme is
    tolerated so a caller may pass the header verbatim.
    """
    if not bearer or len(bearer) > _MAX_BEARER_CHARS:
        return None
    candidate = _BEARER_SCHEME_RE.sub("", bearer.strip(), count=1)
    if len(candidate) != len(prefix) + _SECRET_CHARS or not candidate.startswith(prefix):
        return None
    if not _SECRET_RE.match(candidate[len(prefix) :]):
        return None
    return candidate


def hashes_match(stored: bytes, presented: bytes) -> bool:
    """Constant-time equality for two token hashes."""
    return hmac.compare_digest(stored, presented)
