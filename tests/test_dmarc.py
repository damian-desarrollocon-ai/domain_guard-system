import pytest

from domainguard.models.findings import FindingCategory, Severity
from domainguard.modules.base import ScanContext
from domainguard.modules.dmarc_analysis import DmarcAnalysisModule

from .helpers import FakeResolver, ok, status

D = "example.com"


def txt(name, *records):
    return (name, "TXT"), ok(name, "TXT", *records)


def run(*pairs, domain=D):
    ctx = ScanContext(domain=domain, resolver=FakeResolver(dict(pairs)))
    return DmarcAnalysisModule().run(ctx), ctx


def dmarc(record, domain=D):
    return txt(f"_dmarc.{domain}", record)


def ids(findings):
    return {f.id for f in findings}


def get(findings, fid):
    return next(f for f in findings if f.id == fid)


def test_missing_dmarc_is_confirmed_medium_and_not_overclaiming():
    f, ctx = run()
    assert ids(f) == {"DMARC-001"}
    finding = get(f, "DMARC-001")
    assert finding.severity == Severity.MEDIUM
    assert finding.category == FindingCategory.CONFIRMED
    assert "No prueba" in finding.business_impact
    assert ctx.data["dmarc"]["present"] is False


def test_timeout_makes_no_claim():
    f, ctx = run(((f"_dmarc.{D}", "TXT"), status(f"_dmarc.{D}", "TXT", "timeout")))
    assert ids(f) == {"DMARC-013"}
    assert ctx.data["dmarc"]["present"] is None
    assert ctx.resolver.calls == [(f"_dmarc.{D}", "TXT")]


def test_non_dmarc_txt_is_ignored():
    f, _ = run(txt(f"_dmarc.{D}", "hola mundo"))
    assert ids(f) == {"DMARC-001"}


def test_multiple_records():
    f, ctx = run(txt(f"_dmarc.{D}", "v=DMARC1; p=none", "v=DMARC1; p=reject"))
    assert ids(f) == {"DMARC-002"}
    assert ctx.data["dmarc"]["valid"] is False


def test_reject_with_reports_is_only_summary():
    f, ctx = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com"))
    assert ids(f) == {"DMARC-100"}
    assert ctx.data["dmarc"]["effective_policy"] == "reject"
    assert "p=reject" in get(f, "DMARC-100").technical_explanation


def test_none_with_rua_is_low_potential():
    f, _ = run(dmarc("v=DMARC1; p=none; rua=mailto:r@example.com"))
    assert ids(f) == {"DMARC-004", "DMARC-100"}
    finding = get(f, "DMARC-004")
    assert finding.severity == Severity.LOW
    assert finding.category == FindingCategory.POTENTIAL_RISK
    assert "monitoreo" in finding.technical_explanation


def test_none_without_rua_is_medium():
    f, _ = run(dmarc("v=DMARC1; p=none"))
    assert get(f, "DMARC-004").severity == Severity.MEDIUM


def test_quarantine_is_informational():
    f, _ = run(dmarc("v=DMARC1; p=quarantine; rua=mailto:r@example.com"))
    assert ids(f) == {"DMARC-005", "DMARC-100"}
    assert get(f, "DMARC-005").severity == Severity.INFORMATIONAL


def test_enforcing_without_rua_adds_informational_note():
    f, _ = run(dmarc("v=DMARC1; p=reject"))
    assert ids(f) == {"DMARC-008", "DMARC-100"}
    assert get(f, "DMARC-008").severity == Severity.INFORMATIONAL


def test_pct_partial_and_zero():
    f, _ = run(dmarc("v=DMARC1; p=reject; pct=25; rua=mailto:r@example.com"))
    assert get(f, "DMARC-006").severity == Severity.LOW
    f, _ = run(dmarc("v=DMARC1; p=quarantine; pct=0; rua=mailto:r@example.com"))
    assert get(f, "DMARC-006").severity == Severity.MEDIUM


def test_pct_ignored_when_policy_is_none():
    f, _ = run(dmarc("v=DMARC1; p=none; pct=10; rua=mailto:r@example.com"))
    assert "DMARC-006" not in ids(f)


def test_weaker_subdomain_policy():
    f, _ = run(dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com"))
    assert get(f, "DMARC-007").severity == Severity.MEDIUM
    f, _ = run(dmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:r@example.com"))
    assert get(f, "DMARC-007").severity == Severity.LOW


def test_stronger_or_equal_subdomain_policy_is_fine():
    f, _ = run(dmarc("v=DMARC1; p=quarantine; sp=reject; rua=mailto:r@example.com"))
    assert "DMARC-007" not in ids(f)


def test_fatal_syntax_returns_only_syntax_finding():
    f, ctx = run(dmarc("v=DMARC1; p=block"))
    assert ids(f) == {"DMARC-003"}
    assert get(f, "DMARC-003").severity == Severity.MEDIUM
    assert ctx.data["dmarc"]["valid"] is False
    assert ctx.data["dmarc"]["effective_policy"] is None


def test_warning_only_syntax_is_low_and_analysis_continues():
    f, _ = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com; pct=abc"))
    assert ids(f) == {"DMARC-003", "DMARC-100"}
    assert get(f, "DMARC-003").severity == Severity.LOW


def test_missing_p_with_rua_treated_as_none():
    f, ctx = run(dmarc("v=DMARC1; rua=mailto:r@example.com"))
    assert {"DMARC-003", "DMARC-004"} <= ids(f)
    assert ctx.data["dmarc"]["effective_policy"] == "none"


def test_ruf_is_informational():
    f, _ = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com; ruf=mailto:f@example.com"))
    assert get(f, "DMARC-010").severity == Severity.INFORMATIONAL


def test_strict_alignment_note():
    f, _ = run(dmarc("v=DMARC1; p=reject; adkim=s; rua=mailto:r@example.com"))
    assert get(f, "DMARC-014").severity == Severity.INFORMATIONAL


# ---------------------------------------------------- herencia de subdominios
def test_subdomain_inherits_parent_record():
    sub = "mail.example.com"
    f, ctx = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com", D), domain=sub)
    assert ids(f) == {"DMARC-100"}
    assert ctx.data["dmarc"]["inherited"] is True
    assert ctx.data["dmarc"]["record_domain"] == D
    assert "heredado" in " ".join(get(f, "DMARC-100").evidence)


def test_inherited_effective_policy_uses_sp():
    sub = "mail.example.com"
    f, ctx = run(dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:r@example.com", D), domain=sub)
    assert ctx.data["dmarc"]["effective_policy"] == "none"
    assert {"DMARC-004", "DMARC-007"} <= ids(f)


def test_own_record_wins_over_parent():
    sub = "mail.example.com"
    f, ctx = run(
        dmarc("v=DMARC1; p=none", D),
        dmarc("v=DMARC1; p=reject; rua=mailto:r@example.com", sub),
        domain=sub,
    )
    assert ctx.data["dmarc"]["inherited"] is False
    assert ctx.data["dmarc"]["effective_policy"] == "reject"


def test_parent_lookup_stops_at_two_labels():
    f, ctx = run(domain="a.b.c.example.com")
    assert [c[0] for c in ctx.resolver.calls] == [
        "_dmarc.a.b.c.example.com",
        "_dmarc.b.c.example.com",
        "_dmarc.c.example.com",
        "_dmarc.example.com",
    ]


def test_parent_timeout_is_not_reported_as_missing():
    sub = "mail.example.com"
    f, _ = run(((f"_dmarc.{D}", "TXT"), status(f"_dmarc.{D}", "TXT", "timeout")), domain=sub)
    assert ids(f) == {"DMARC-013"}


# ---------------------------------------------------- destinos externos
def test_internal_report_destinations_are_not_checked():
    f, ctx = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@reports.example.com"))
    assert "DMARC-012" not in ids(f)
    assert all("_report._dmarc" not in c[0] for c in ctx.resolver.calls)


def test_external_destination_without_authorization():
    f, ctx = run(dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.net"))
    assert "DMARC-012" in ids(f)
    assert get(f, "DMARC-012").severity == Severity.LOW
    assert ctx.data["dmarc"]["external_unauthorized"]


def test_external_destination_with_authorization():
    f, _ = run(
        dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.net"),
        txt(f"{D}._report._dmarc.vendor.net", "v=DMARC1"),
    )
    assert "DMARC-012" not in ids(f)


def test_external_check_timeout_is_incomplete_not_unauthorized():
    f, _ = run(
        dmarc("v=DMARC1; p=reject; rua=mailto:r@vendor.net"),
        ((f"{D}._report._dmarc.vendor.net", "TXT"), status("x", "TXT", "timeout")),
    )
    assert "DMARC-012" not in ids(f) and "DMARC-013" in ids(f)


def test_external_checks_are_capped():
    uris = ",".join(f"mailto:r@v{i}.net" for i in range(8))
    f, ctx = run(dmarc(f"v=DMARC1; p=reject; rua={uris}"))
    external_calls = [c for c in ctx.resolver.calls if "_report._dmarc" in c[0]]
    assert len(external_calls) == 5
    assert "DMARC-013" in ids(f)


def test_skipped_when_domain_does_not_exist():
    ctx = ScanContext(domain=D, resolver=FakeResolver({}))
    ctx.data["domain_exists"] = False
    assert DmarcAnalysisModule().run(ctx) == []
    assert ctx.resolver.calls == []