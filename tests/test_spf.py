import pytest

from domainguard.core.resolver import DnsAnswer
from domainguard.models.findings import FindingCategory, Severity
from domainguard.modules.base import ScanContext
from domainguard.modules.spf_analysis import SpfAnalysisModule, parse_spf

from .helpers import FakeResolver, ok, status

D = "example.com"


def run_spf(records):
    answers = {}
    for name, rec in records.items():
        if isinstance(rec, DnsAnswer):
            answers[(name, "TXT")] = rec
        elif isinstance(rec, str):
            answers[(name, "TXT")] = ok(name, "TXT", rec)
        else:
            answers[(name, "TXT")] = ok(name, "TXT", *rec)
    ctx = ScanContext(domain=D, resolver=FakeResolver(answers))
    return SpfAnalysisModule().run(ctx), ctx


def ids(findings):
    return {f.id for f in findings}


def by_id(findings, fid):
    return next(f for f in findings if f.id == fid)


# ------------------------------------------------------------------ parser
def test_parse_valid_record():
    p = parse_spf("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all exp=explain.example.com")
    assert p.errors == []
    assert [t.name for t in p.terms] == ["ip4", "include", "all", "exp"]


@pytest.mark.parametrize(
    "term",
    ["foo", "allx", "include", "include:", "ip4:999.1.1.1", "ip4:2001:db8::/32",
     "a/99", "mx:/24", "redirect="],
)
def test_parse_invalid_terms(term):
    assert parse_spf(f"v=spf1 {term}").errors


def test_parse_duplicate_redirect():
    p = parse_spf("v=spf1 redirect=a.example.net redirect=b.example.net")
    assert any("más de una vez" in e for e in p.errors)


# ------------------------------------------------------------------ módulo
def test_healthy_spf_only_summary():
    f, ctx = run_spf({
        D: "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all",
        "_spf.example.net": "v=spf1 ip4:198.51.100.0/24 -all",
    })
    assert ids(f) == {"SPF-100"}
    assert ctx.data["spf"]["lookup_count"] == 1
    assert ctx.data["spf"]["all_qualifier"] == "-"


def test_no_spf_record():
    f, ctx = run_spf({D: "google-site-verification=abc"})
    assert ids(f) == {"SPF-001"}
    assert ctx.data["spf"]["present"] is False


def test_multiple_spf_records():
    f, ctx = run_spf({D: ["v=spf1 -all", "v=spf1 +all"]})
    assert ids(f) == {"SPF-002"}
    assert ctx.data["spf"]["permerror"] is True


def test_txt_timeout_makes_no_claims():
    f, ctx = run_spf({D: status(D, "TXT", "timeout")})
    assert ids(f) == {"SPF-013"}
    assert ctx.data["spf"]["present"] is None


def test_skipped_when_domain_does_not_exist():
    ctx = ScanContext(domain=D, resolver=FakeResolver({}))
    ctx.data["domain_exists"] = False
    assert SpfAnalysisModule().run(ctx) == []


def test_plus_all_is_critical():
    f, _ = run_spf({D: "v=spf1 ip4:192.0.2.1 +all"})
    assert ids(f) == {"SPF-004", "SPF-100"}
    assert by_id(f, "SPF-004").severity == Severity.CRITICAL
    assert by_id(f, "SPF-004").category == FindingCategory.CONFIRMED


def test_bare_all_is_treated_as_plus_all():
    f, _ = run_spf({D: "v=spf1 all"})
    assert "SPF-004" in ids(f)


def test_neutral_all():
    f, _ = run_spf({D: "v=spf1 ip4:192.0.2.1 ?all"})
    assert ids(f) == {"SPF-005", "SPF-100"}


def test_softfail_is_informational_only():
    f, _ = run_spf({D: "v=spf1 ip4:192.0.2.1 ~all"})
    assert ids(f) == {"SPF-006", "SPF-100"}
    assert by_id(f, "SPF-006").severity == Severity.INFORMATIONAL


def test_no_all_and_no_redirect():
    f, _ = run_spf({D: "v=spf1 ip4:192.0.2.1"})
    assert ids(f) == {"SPF-007", "SPF-100"}


def test_policy_obtained_through_redirect():
    f, ctx = run_spf({
        D: "v=spf1 redirect=_spf.example.net",
        "_spf.example.net": "v=spf1 ip4:192.0.2.1 +all",
    })
    assert ids(f) == {"SPF-004", "SPF-100"}
    assert ctx.data["spf"]["lookup_count"] == 1


def _includes(n):
    recs = {D: "v=spf1 " + " ".join(f"include:i{k}.example.net" for k in range(n)) + " -all"}
    for k in range(n):
        recs[f"i{k}.example.net"] = "v=spf1 -all"
    return recs


def test_eleven_lookups_exceed_limit():
    f, ctx = run_spf(_includes(11))
    assert ids(f) == {"SPF-008", "SPF-100"}
    assert by_id(f, "SPF-008").category == FindingCategory.POTENTIAL_RISK
    assert ctx.data["spf"]["lookup_count"] == 11


def test_exactly_ten_lookups_is_only_a_warning():
    f, _ = run_spf(_includes(10))
    assert ids(f) == {"SPF-009", "SPF-100"}


def test_hard_cap_truncates_and_reports_incomplete():
    f, ctx = run_spf(_includes(40))
    assert {"SPF-008", "SPF-013", "SPF-100"} <= ids(f)
    assert ctx.data["spf"]["lookup_count"] == 30


def test_nested_lookups_are_counted():
    f, ctx = run_spf({
        D: "v=spf1 include:a.example.net -all",
        "a.example.net": "v=spf1 mx a -all",
    })
    assert ids(f) == {"SPF-100"}
    assert ctx.data["spf"]["lookup_count"] == 3


def test_include_loop_detected():
    f, _ = run_spf({
        D: "v=spf1 include:x.example.net -all",
        "x.example.net": "v=spf1 include:example.com -all",
    })
    assert ids(f) == {"SPF-010", "SPF-100"}


def test_include_to_domain_without_spf():
    f, ctx = run_spf({
        D: "v=spf1 include:nospf.example.net -all",
        "nospf.example.net": "hello",
    })
    assert ids(f) == {"SPF-011", "SPF-100"}
    assert ctx.data["spf"]["permerror"] is True


def test_include_timeout_is_not_reported_as_missing_spf():
    f, _ = run_spf({
        D: "v=spf1 include:slow.example.net -all",
        "slow.example.net": status("slow.example.net", "TXT", "timeout"),
    })
    assert ids(f) == {"SPF-013", "SPF-100"}


def test_ptr_mechanism_flagged():
    f, _ = run_spf({D: "v=spf1 ptr -all"})
    assert ids(f) == {"SPF-012", "SPF-100"}


def test_broad_ip_range_flagged():
    f, _ = run_spf({D: "v=spf1 ip4:10.0.0.0/8 -all"})
    assert ids(f) == {"SPF-014", "SPF-100"}
    assert by_id(f, "SPF-014").severity == Severity.MEDIUM


def test_terms_after_all_are_ignored_and_not_counted():
    f, ctx = run_spf({D: "v=spf1 -all include:foo.example.net"})
    assert ids(f) == {"SPF-015", "SPF-100"}
    assert ctx.data["spf"]["lookup_count"] == 0


def test_syntax_error_sets_permerror():
    f, ctx = run_spf({D: "v=spf1 foo -all"})
    assert "SPF-003" in ids(f)
    assert ctx.data["spf"]["permerror"] is True