"""Which address gets recorded, and what an attacker can do about it.

``X-Forwarded-For`` is a header anyone can send. These tests are the ones that matter: the value is
believed only when the peer is a configured proxy, and only as far back as the chain stays inside
trusted addresses.
"""

from __future__ import annotations

import pytest

from esign.identity.client_ip import client_ip, parse_trusted_proxies

PROXIES = ("10.0.0.0/8", "2001:db8::/32")


def test_no_peer_means_no_recorded_address() -> None:
    assert client_ip(None, "203.0.113.9", PROXIES) is None
    assert client_ip("", "203.0.113.9", PROXIES) is None
    assert client_ip("not-an-address", "203.0.113.9", PROXIES) is None


def test_an_untrusted_peer_cannot_claim_to_be_a_proxy() -> None:
    """The spoofing case: a client sends its own X-Forwarded-For and it is ignored."""
    assert client_ip("203.0.113.9", "198.51.100.1", PROXIES) == "203.0.113.9"
    assert client_ip("203.0.113.9", "127.0.0.1, 10.0.0.1", PROXIES) == "203.0.113.9"


def test_with_no_configured_proxies_the_header_is_never_believed() -> None:
    assert client_ip("10.0.0.5", "203.0.113.9", ()) == "10.0.0.5"


def test_a_trusted_proxy_is_believed() -> None:
    assert client_ip("10.0.0.5", "203.0.113.9", PROXIES) == "203.0.113.9"


def test_the_rightmost_untrusted_address_wins() -> None:
    """Entries to the left of the real client are whatever the client chose to send."""
    forwarded = "1.1.1.1, 203.0.113.9, 10.0.0.7"
    assert client_ip("10.0.0.5", forwarded, PROXIES) == "203.0.113.9"


def test_a_client_that_forges_a_longer_chain_does_not_get_believed() -> None:
    forwarded = "8.8.8.8, 9.9.9.9"  # both sent by the client itself
    assert client_ip("10.0.0.5", forwarded, PROXIES) == "9.9.9.9"


def test_a_malformed_entry_stops_the_walk_at_the_proxy() -> None:
    assert client_ip("10.0.0.5", "203.0.113.9, unknown", PROXIES) == "10.0.0.5"
    assert client_ip("10.0.0.5", "203.0.113.9, <script>", PROXIES) == "10.0.0.5"
    assert client_ip("10.0.0.5", ",", PROXIES) == "10.0.0.5"


def test_a_chain_of_nothing_but_proxies_records_the_peer() -> None:
    assert client_ip("10.0.0.5", "10.0.0.1, 10.0.0.2", PROXIES) == "10.0.0.5"


def test_ports_and_brackets_are_tolerated() -> None:
    assert client_ip("10.0.0.5:4444", "203.0.113.9:1234", PROXIES) == "203.0.113.9"
    assert client_ip("[2001:db8::1]:443", "[2001:db8:ffff::9]", ("2001:db8::/48",)) == "2001:db8:ffff::9"


def test_ipv6_and_ipv4_ranges_do_not_bleed_into_each_other() -> None:
    assert client_ip("2001:db8::1", "203.0.113.9", ("10.0.0.0/8",)) == "2001:db8::1"


def test_the_address_is_canonicalised() -> None:
    assert client_ip("10.0.0.5", "2606:4700:0000:0000:0000:0000:0000:0009", PROXIES) == "2606:4700::9"


def test_a_very_long_header_is_bounded() -> None:
    forwarded = ", ".join(["10.0.0.1"] * 5000) + ", 203.0.113.9, 10.0.0.2"
    assert client_ip("10.0.0.5", forwarded, PROXIES) == "203.0.113.9"


def test_an_empty_header_records_the_peer() -> None:
    assert client_ip("10.0.0.5", "", PROXIES) == "10.0.0.5"
    assert client_ip("10.0.0.5", None, PROXIES) == "10.0.0.5"


def test_a_misconfigured_cidr_is_loud_where_it_is_parsed() -> None:
    with pytest.raises(ValueError, match="not appear to be"):
        parse_trusted_proxies(("10.0.0.0/8", "nonsense"))


def test_a_misconfigured_cidr_never_widens_trust_at_request_time() -> None:
    """If configuration is broken, no header is believed -- the peer is what gets recorded."""
    assert client_ip("10.0.0.5", "203.0.113.9", ("nonsense",)) == "10.0.0.5"


def test_host_bits_in_a_cidr_are_tolerated() -> None:
    assert parse_trusted_proxies(("10.1.2.3/8",))[0].prefixlen == 8
