import pytest

from domainguard.models.findings import FindingCategory, Severity
from domainguard.modules.base import ScanContext
from domainguard.modules.spoofing_analysis import SpoofingAnalysisModule

from .helpers import FakeResolver, ok

D = "example.com"


def spf(q="-", present=True, multiple=False, permerror=False, record=None):
    return {"present": present, "multiple": multiple, "permerror": permerror,
            "all_qualifier": q, "record": record}


def dmarc(policy="reject", pct=100, sp=None, present=True, valid=True, p=None):
    return {"present": present, "valid": valid, "effective_policy": policy, "pct": pct,
            "policy": p or policy, "subdomain_policy": sp}


def dkim(valid=("google",), bits=2048):
    return {"valid": list(valid), "min_rsa_bits": bits if valid else None}


def run(spf_d, dmarc_d, dkim_d=None, mx=None, domain_exists=True):
    ctx = ScanContext(domain=D, resolver=FakeResolver())
    ctx.data["domain_exists"] = domain_exists
    if spf_d is not None:
        ctx.data["spf"] = spf_d
    if dmarc_d is not None:
        ctx.data["dmarc"] = dmarc_d
    if dkim_d is not None:
        ctx.data["dkim"] = dkim_d
    if mx is not None:
        ctx.data["dns"] = {"MX": mx}
    return SpoofingAnalysisModule().run(ctx), ctx


def level(ctx):
    return ctx.data["spoofing"]["level"]


def test_full_enforcement_is_minimal_and_informational():
    f, ctx = run(spf("-"), dmarc("reject"), dkim())
    assert [x.id for x in f] == ["SPOOF-100"]
    assert f[0].severity == Severity.INFORMATIONAL
    assert level(ctx) == "MINIMAL"


def test_quarantine_pct100_is_minimal():
    _, ctx = run(spf("~"), dmarc("quarantine"), dkim())
    assert level(ctx) == "MINIMAL"


def test_plus_all_defeats_reject():
    f, ctx = run(spf("+"), dmarc("reject"), dkim())
    assert level(ctx) == "ELEVATED"
    assert f[0].severity == Severity.HIGH
    assert f[0].category == FindingCategory.POTENTIAL_RISK
    assert "+all" in f[0].remediation


@pytest.mark.parametrize(
    "spf_d, expected",
    [
        (spf("-"), "MODERATE"),
        (spf("~"), "MODERATE"),
        (spf("?"), "ELEVATED"),
        (spf(None, present=False), "ELEVATED"),
        (spf("-", multiple=True), "ELEVATED"),
        (spf("-", permerror=True), "ELEVATED"),
    ],
)
def test_no_dmarc_depends_on_spf_controls(spf_d, expected):
    _, ctx = run(spf_d, dmarc(None, present=False, valid=False))
    assert level(ctx) == expected


def test_invalid_dmarc_counts_as_absent():
    _, ctx = run(spf("-"), dmarc(None, present=True, valid=False))
    assert level(ctx) == "MODERATE"


@pytest.mark.parametrize(
    "spf_d, expected", [(spf("~"), "MODERATE"), (spf("?"), "ELEVATED"), (spf("-"), "MODERATE")]
)
def test_monitor_policy(spf_d, expected):
    _, ctx = run(spf_d, dmarc("none"))
    assert level(ctx) == expected


def test_partial_pct_is_limited_low():
    f, ctx = run(spf("-"), dmarc("reject", pct=50))
    assert level(ctx) == "LIMITED"
    assert f[0].severity == Severity.LOW


def test_pct_zero_is_like_monitoring():
    _, ctx = run(spf("-"), dmarc("quarantine", pct=0))
    assert level(ctx) == "MODERATE"


def test_weaker_subdomain_policy_is_limited_only():
    f, ctx = run(spf("-"), dmarc("reject", sp="none", p="reject"), dkim())
    assert level(ctx) == "LIMITED"
    assert any("sp=none" in line for line in f[0].evidence)


def test_equal_subdomain_policy_is_fine():
    _, ctx = run(spf("-"), dmarc("reject", sp="reject", p="reject"), dkim())
    assert level(ctx) == "MINIMAL"


def test_weak_dkim_key_raises_to_moderate():
    f, ctx = run(spf("-"), dmarc("reject"), dkim(bits=512))
    assert level(ctx) == "MODERATE"
    assert f[0].severity == Severity.MEDIUM
    assert "512" in " ".join(f[0].evidence)


def test_missing_dkim_selectors_do_not_raise_risk():
    f, ctx = run(spf("-"), dmarc("reject"), dkim(valid=()))
    assert level(ctx) == "MINIMAL"
    assert "no concluyente" in " ".join(f[0].evidence)


def test_dkim_not_run_does_not_raise_risk():
    _, ctx = run(spf("-"), dmarc("reject"), None)
    assert level(ctx) == "MINIMAL"


@pytest.mark.parametrize(
    "spf_d, dmarc_d",
    [(spf(None, present=None), dmarc("reject")), (spf("-"), dmarc(None, present=None)),
     (None, dmarc("reject")), (spf("-"), None)],
)
def test_indeterminate_when_data_missing_or_incomplete(spf_d, dmarc_d):
    f, ctx = run(spf_d, dmarc_d)
    assert [x.id for x in f] == ["SPOOF-002"]
    assert f[0].severity == Severity.INFORMATIONAL
    assert f[0].category == FindingCategory.REQUIRES_VALIDATION
    assert level(ctx) == "INDETERMINATE"


def test_non_sending_domain_gets_reject_recommendation():
    mx = ok(D, "MX", "0 .")
    f, _ = run(spf("-", record="v=spf1 -all"), dmarc(None, present=False, valid=False), mx=mx)
    assert "p=reject" in f[0].remediation
    assert any("no enviar correo" in line for line in f[0].evidence)


def test_sending_domain_is_not_flagged_as_non_sending():
    mx = ok(D, "MX", "10 mail.example.com.")
    f, _ = run(spf("-", record="v=spf1 -all"), dmarc("none"), mx=mx)
    assert not any("no enviar correo" in line for line in f[0].evidence)


def test_every_finding_states_dns_only_limitation_and_authorization():
    for spf_d, dmarc_d in [(spf("+"), dmarc("reject")), (spf("-"), dmarc("reject")), (None, None)]:
        f, _ = run(spf_d, dmarc_d, dkim())
        text = f[0].validation_limitations
        assert "únicamente en DNS" in text and "autorización" in text


def test_never_claims_confirmed_vulnerability():
    for spf_d, dmarc_d in [(spf("+"), dmarc("reject")), (spf(None, present=False), dmarc("none"))]:
        f, _ = run(spf_d, dmarc_d)
        assert f[0].category != FindingCategory.CONFIRMED
        assert "vulnerable" not in (f[0].title + f[0].description + f[0].business_impact).lower()


def test_skipped_when_domain_does_not_exist():
    f, ctx = run(spf("-"), dmarc("reject"), domain_exists=False)
    assert f == [] and "spoofing" not in ctx.data