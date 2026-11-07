import dns.exception
import dns.resolver
import pytest

from domainguard.core.resolver import DnsResolver, QueryLimitExceeded


def _stub(resolver: DnsResolver, exc: Exception) -> dict:
    calls = {"n": 0}

    def fake(*args, **kwargs):
        calls["n"] += 1
        raise exc

    resolver._resolver.resolve = fake
    return calls


@pytest.mark.parametrize(
    "exc, status",
    [
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        (dns.resolver.NoAnswer(), "no_data"),
        (dns.exception.Timeout(), "timeout"),
        (dns.resolver.NoNameservers(), "servfail"),
    ],
)
def test_error_mapping(exc, status):
    r = DnsResolver()
    _stub(r, exc)
    assert r.query("example.com", "TXT").status == status


def test_cache_avoids_repeated_queries():
    r = DnsResolver()
    calls = _stub(r, dns.resolver.NoAnswer())
    r.query("Example.com", "txt")
    r.query("example.com.", "TXT")
    assert calls["n"] == 1
    assert r.queries_made == 1


def test_query_limit():
    r = DnsResolver(max_queries=2)
    _stub(r, dns.resolver.NoAnswer())
    r.query("a.example.com", "A")
    r.query("b.example.com", "A")
    with pytest.raises(QueryLimitExceeded):
        r.query("c.example.com", "A")