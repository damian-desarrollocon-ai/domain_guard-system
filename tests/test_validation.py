import pytest

from domainguard.core.validation import (
    DomainValidationError,
    is_public_ip,
    validate_domain,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  sub.example.co.uk ", "sub.example.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_valid_domains(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "", "   ", "http://example.com", "example.com/path", "example.com:443",
        "user@example.com", "127.0.0.1", "192.168.1.1", "[::1]", "localhost",
        "intranet.local", "example", "-bad.com", "a" * 64 + ".com",
        "exa mple.com", "example.123", "2130706433",
    ],
)
def test_invalid_domains(raw):
    with pytest.raises(DomainValidationError):
        validate_domain(raw)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
def test_public_ips(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize(
    "ip", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.0.5", "::1", "garbage"]
)
def test_non_public_ips(ip):
    assert not is_public_ip(ip)