import pytest

from domainguard.models.findings import FindingCategory, Severity
from domainguard.modules.base import ScanContext
from domainguard.modules.dkim_analysis import DkimAnalysisModule

from .helpers import FakeResolver, ok, status
from .test_dkim_parse import REAL_RSA_1024, REAL_RSA_2048, b64, synthetic_spki

D = "example.com"


def name(sel):
    return f"{sel}._domainkey.{D}"


def run(records, selectors=None):
    answers = {}
    for sel, rec in records.items():
        if hasattr(rec, "status"):
            answers[(name(sel), "TXT")] = rec
        else:
            answers[(name(sel), "TXT")] = ok(name(sel), "TXT", rec)
    ctx = ScanContext(domain=D, resolver=FakeResolver(answers))
    return DkimAnalysisModule(selectors).run(ctx), ctx


def ids(findings):
    return {f.id for f in findings}


def get(findings, fid):
    return next(f for f in findings if f.id == fid)


def test_default_selectors_are_configurable_and_deduplicated():
    assert len(DkimAnalysisModule().selectors) == 10
    assert DkimAnalysisModule([" Google ", "google", "k2"]).selectors == ["google", "k2"]


@pytest.mark.parametrize("bad", ["", "a b", "a..b", "-x", "x/y", "a" * 200])
def test_invalid_selector_rejected(bad):
    with pytest.raises(ValueError):
        DkimAnalysisModule([bad])


def test_no_selectors_found_is_low_confidence_and_needs_validation():
    f, ctx = run({})
    assert ids(f) == {"DKIM-001"}
    finding = get(f, "DKIM-001")
    assert finding.severity == Severity.INFORMATIONAL
    assert finding.category == FindingCategory.REQUIRES_VALIDATION
    assert "no prueba" in finding.validation_limitations
    assert ctx.data["dkim"]["valid"] == []


def test_all_timeouts_make_no_claim_of_absence():
    selectors = ["google", "default"]
    f, ctx = run(
        {s: status(name(s), "TXT", "timeout") for s in selectors}, selectors
    )
    assert ids(f) == {"DKIM-008"}
    assert ctx.data["dkim"]["incomplete"] is True


def test_valid_2048_key_only_summary():
    f, ctx = run({"google": f"v=DKIM1; k=rsa; p={REAL_RSA_2048}"})
    assert ids(f) == {"DKIM-100"}
    assert "RSA 2048 bits" in get(f, "DKIM-100").evidence[0]
    assert ctx.data["dkim"]["valid"] == ["google"]
    assert ctx.data["dkim"]["min_rsa_bits"] == 2048


def test_1024_key_is_low():
    f, _ = run({"default": f"v=DKIM1; p={REAL_RSA_1024}"})
    assert ids(f) == {"DKIM-006", "DKIM-100"}
    assert get(f, "DKIM-006").severity == Severity.LOW


def test_512_key_is_high_and_confirmed():
    f, ctx = run({"s1": f"v=DKIM1; k=rsa; p={b64(synthetic_spki(512))}"})
    assert ids(f) == {"DKIM-005", "DKIM-100"}
    assert get(f, "DKIM-005").severity == Severity.HIGH
    assert get(f, "DKIM-005").category == FindingCategory.CONFIRMED
    assert ctx.data["dkim"]["min_rsa_bits"] == 512


def test_revoked_key_is_informational_and_not_valid():
    f, ctx = run({"old": "v=DKIM1; k=rsa; p="}, ["old"])
    assert ids(f) == {"DKIM-004"}
    assert get(f, "DKIM-004").severity == Severity.INFORMATIONAL
    assert ctx.data["dkim"]["valid"] == []
    assert ctx.data["dkim"]["revoked"] == ["old"]


def test_broken_record_alone_is_medium():
    f, ctx = run({"mail": "v=DKIM1; k=rsa"}, ["mail"])
    assert ids(f) == {"DKIM-003"}
    assert get(f, "DKIM-003").severity == Severity.MEDIUM
    assert ctx.data["dkim"]["invalid"] == ["mail"]


def test_broken_record_next_to_valid_one_is_low():
    f, _ = run({
        "mail": "v=DKIM1; k=rsa",
        "google": f"v=DKIM1; p={REAL_RSA_2048}",
    })
    assert ids(f) == {"DKIM-003", "DKIM-100"}
    assert get(f, "DKIM-003").severity == Severity.LOW


def test_testing_mode_flag():
    f, ctx = run({"google": f"v=DKIM1; p={REAL_RSA_2048}; t=y"})
    assert ids(f) == {"DKIM-007", "DKIM-100"}
    assert ctx.data["dkim"]["testing"] == ["google"]


def test_t_s_flag_is_not_testing():
    f, _ = run({"google": f"v=DKIM1; p={REAL_RSA_2048}; t=s"})
    assert ids(f) == {"DKIM-100"}


def test_non_dkim_txt_at_selector_is_ignored():
    f, _ = run({"google": "hola mundo"}, ["google"])
    assert ids(f) == {"DKIM-001"}


def test_partial_timeout_plus_found_key_reports_both():
    f, _ = run({
        "google": f"v=DKIM1; p={REAL_RSA_2048}",
        "default": status(name("default"), "TXT", "timeout"),
    }, ["google", "default"])
    assert ids(f) == {"DKIM-008", "DKIM-100"}


def test_skipped_when_domain_does_not_exist():
    ctx = ScanContext(domain=D, resolver=FakeResolver({}))
    ctx.data["domain_exists"] = False
    assert DkimAnalysisModule().run(ctx) == []
    assert ctx.resolver.calls == []


def test_only_selector_names_are_queried():
    ctx = ScanContext(domain=D, resolver=FakeResolver({}))
    DkimAnalysisModule(["google", "k1"]).run(ctx)
    assert ctx.resolver.calls == [
        (name("google"), "TXT"),
        (name("k1"), "TXT"),
    ]