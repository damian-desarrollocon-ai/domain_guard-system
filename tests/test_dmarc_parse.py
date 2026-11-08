import pytest

from domainguard.core.dmarc_parse import is_dmarc_record, parse_dmarc


@pytest.mark.parametrize(
    "text, expected",
    [
        ("v=DMARC1; p=none", True),
        ("  V=dmarc1;p=reject", True),
        ("v=DMARC1", True),
        ("p=none; v=DMARC1", False),
        ("v=DMARC2; p=none", False),
        ("v=spf1 -all", False),
    ],
)
def test_is_dmarc_record(text, expected):
    assert is_dmarc_record(text) is expected


def test_full_record():
    r = parse_dmarc(
        "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; "
        "rua=mailto:a@example.com,mailto:b@example.org!10m; ruf=mailto:f@example.com"
    )
    assert r.fatal == [] and r.warnings == []
    assert (r.policy, r.subdomain_policy, r.pct, r.adkim, r.aspf) == ("quarantine", "reject", 50, "s", "r")
    assert r.rua == ["a@example.com", "b@example.org"]
    assert r.ruf == ["f@example.com"]


def test_defaults():
    r = parse_dmarc("v=DMARC1; p=reject")
    assert (r.pct, r.adkim, r.aspf, r.rua, r.subdomain_policy) == (100, "r", "r", [], None)


def test_values_are_case_insensitive():
    assert parse_dmarc("v=DMARC1; p=REJECT; adkim=S").policy == "reject"


def test_missing_p_without_rua_is_fatal():
    r = parse_dmarc("v=DMARC1; pct=100")
    assert r.fatal and r.policy is None


def test_invalid_p_without_rua_is_fatal():
    r = parse_dmarc("v=DMARC1; p=block")
    assert r.fatal and r.policy is None


def test_missing_p_with_valid_rua_is_treated_as_none():
    r = parse_dmarc("v=DMARC1; rua=mailto:a@example.com")
    assert r.fatal == [] and r.policy == "none" and r.treated_as_none
    assert r.warnings


def test_invalid_p_with_invalid_rua_is_fatal():
    r = parse_dmarc("v=DMARC1; p=block; rua=http://x.example.com")
    assert r.fatal


@pytest.mark.parametrize("pct", ["abc", "101", "-5", "1000", ""])
def test_invalid_pct_falls_back_to_100(pct):
    r = parse_dmarc(f"v=DMARC1; p=none; pct={pct}")
    assert r.pct == 100 and r.warnings


def test_invalid_alignment_and_sp_values():
    r = parse_dmarc("v=DMARC1; p=none; adkim=x; aspf=y; sp=zzz")
    assert (r.adkim, r.aspf, r.subdomain_policy) == ("r", "r", None)
    assert len(r.warnings) == 3


@pytest.mark.parametrize(
    "rua",
    ["mailto:not-an-email", "mailto:", "https://example.com/r", "a@example.com"],
)
def test_invalid_report_uris_are_warnings(rua):
    r = parse_dmarc(f"v=DMARC1; p=none; rua={rua}")
    assert r.rua == [] and r.warnings and not r.fatal


def test_v_not_first_is_fatal():
    assert parse_dmarc("p=none; v=DMARC1").fatal


def test_duplicate_tags_are_reported():
    r = parse_dmarc("v=DMARC1; p=none; p=reject")
    assert r.policy == "none" and r.warnings