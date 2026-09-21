"""Token shape, entropy and parsing. No database: this is arithmetic and string handling."""

from __future__ import annotations

import re

import pytest

from esign.identity.tokens import (
    HOST_KEY_PREFIX,
    SESSION_TOKEN_PREFIX,
    TOKEN_LENGTH,
    hashes_match,
    mint_token,
    parse_token,
    token_sha256,
)

PREFIXES = [HOST_KEY_PREFIX, SESSION_TOKEN_PREFIX]
_BASE64URL = re.compile(r"\A[A-Za-z0-9_-]+\Z")


@pytest.mark.parametrize("prefix", PREFIXES)
def test_a_minted_token_has_the_documented_shape(prefix: str) -> None:
    token = mint_token(prefix)
    assert token.startswith(prefix)
    assert len(token) == TOKEN_LENGTH
    assert _BASE64URL.match(token[len(prefix) :])


@pytest.mark.parametrize("prefix", PREFIXES)
def test_tokens_carry_256_bits_of_entropy(prefix: str) -> None:
    """A weak generator shows up as repeats long before it shows up as a breach."""
    minted = {mint_token(prefix) for _ in range(2000)}
    assert len(minted) == 2000
    # 43 unpadded base64url characters is exactly 256 bits.
    assert len(minted.pop()) - len(prefix) == 43


def test_mint_refuses_an_unknown_prefix() -> None:
    with pytest.raises(ValueError, match="prefix"):
        mint_token("xyz_")


def test_the_hash_is_32_bytes_and_stable() -> None:
    token = mint_token(SESSION_TOKEN_PREFIX)
    assert len(token_sha256(token)) == 32
    assert token_sha256(token) == token_sha256(token)
    assert token_sha256(token) != token_sha256(mint_token(SESSION_TOKEN_PREFIX))


def test_the_hash_covers_the_prefix_too() -> None:
    """Otherwise a host key and a session token with the same random part would collide."""
    token = mint_token(SESSION_TOKEN_PREFIX)
    secret = token[len(SESSION_TOKEN_PREFIX) :]
    assert token_sha256(token) != token_sha256(HOST_KEY_PREFIX + secret)


@pytest.mark.parametrize("prefix", PREFIXES)
def test_parse_accepts_the_bare_token_and_an_authorization_header(prefix: str) -> None:
    token = mint_token(prefix)
    assert parse_token(token, prefix) == token
    assert parse_token(f"Bearer {token}", prefix) == token
    assert parse_token(f"bearer  {token}", prefix) == token
    assert parse_token(f"  {token}  ", prefix) == token


@pytest.mark.parametrize(
    "bearer",
    [
        None,
        "",
        "   ",
        "Bearer ",
        "esk_",
        "est_short",
        "est_" + "a" * 42,
        "est_" + "a" * 44,
        "est_" + "a" * 42 + "!",
        "est_" + "a" * 42 + "=",
        "est_" + "a" * 42 + " ",
        "esk_" + "a" * 43,  # right shape, wrong prefix for a session token
        "Basic est_" + "a" * 43,
        "est_" + "a" * 43 + "; DROP TABLE hosts",
        "x" * 5000,
    ],
)
def test_parse_rejects_anything_that_is_not_a_session_token(bearer: str | None) -> None:
    assert parse_token(bearer, SESSION_TOKEN_PREFIX) is None


def test_parse_never_raises_on_hostile_input() -> None:
    for candidate in ("\x00" * 10, "est_\n" + "a" * 39, "🔐" * 20, "est_%s" % ("a" * 43)):
        parse_token(candidate, SESSION_TOKEN_PREFIX)


def test_hashes_match_compares_equal_and_unequal_values() -> None:
    first = token_sha256(mint_token(SESSION_TOKEN_PREFIX))
    second = token_sha256(mint_token(SESSION_TOKEN_PREFIX))
    assert hashes_match(first, bytes(first))
    assert not hashes_match(first, second)
    assert not hashes_match(first, first[:-1])
