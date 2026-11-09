from datetime import datetime, timedelta, timezone

import pytest

from domainguard import __version__
from domainguard.core.scanner import Scanner, build_default_modules
from domainguard.core.validation import DomainValidationError
from domainguard.models.findings import Severity
from domainguard.modules.base import BaseModule
from domainguard.modules.dkim_analysis import DkimAnalysisModule
from domainguard.modules.dns_analysis import DnsAnalysisModule
from domainguard.modules.spf_analysis import SpfAnalysisModule

from .helpers import FakeResolver, ok, status
from .test_dkim_parse import REAL_RSA_2048

D = "example.com"
MODULE_ORDER = ["dns_analysis", "spf_analysis", "dkim_analysis", "dmarc_analysis", "spoofing_analysis"]


def good_domain():
    return {
        (D, "A"): ok(D, "A", "93.184.216.34"),
        (D, "NS"): ok(D, "NS", "ns1.example.net.", "ns2.example.net."),
        (D, "TXT"): ok(D, "TXT", "v=spf1 ip4:192.0.2.0/24 -all"),
        (f"google._domainkey.{D}", "TXT"): ok("x", "TXT", f"v=DKIM1; k=rsa; p={REAL_RSA_2048}"),
        (f"_dmarc.{D}", "TXT"): ok("x", "TXT", "v=DMARC1; p=reject; rua=mailto:r@example.com"),
    }


def bare_domain():
    return {(D, "A"): ok(D, "A", "93.184.216.34"), (D, "NS"): ok(D, "NS", "ns1.x.net.", "ns2.x.net.")}


def scanner(answers, **kwargs):
    return Scanner(resolver_factory=lambda: FakeResolver(answers), **kwargs)


def ids(result):
    return {f.id for f in result.findings}


def test_well_configured_domain_scores_100():
    r = scanner(good_domain()).scan(D)
    assert ids(r) == {"SPF-100", "DKIM-100", "DMARC-100", "SPOOF-100"}
    assert (r.risk.score, r.risk.grade) == (100, "A")
    assert r.assessed is True and r.risk.partial is False
    assert [m.name for m in r.modules] == MODULE_ORDER
    assert all(m.status == "completed" for m in r.modules)


def test_unprotected_domain_scores_69_with_expected_findings():
    r = scanner(bare_domain()).scan(D)
    assert ids(r) == {"SPF-001", "DKIM-001", "DMARC-001", "SPOOF-001"}
    assert r.risk.score == 69 and r.risk.ceiling_applied == "HIGH"
    assert r.risk.grade == "C"


def test_findings_are_sorted_by_severity_then_id():
    r = scanner(bare_domain()).scan(D)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
    ranks = [order.index(f.severity) for f in r.findings]
    assert ranks == sorted(ranks)
    assert [f.id for f in r.findings][:3] == ["SPOOF-001", "DMARC-001", "SPF-001"]


def test_nonexistent_domain_skips_modules_and_is_not_assessed():
    r = scanner({(D, "A"): status(D, "A", "nxdomain")}).scan(D)
    assert ids(r) == {"DNS-001"}
    assert r.assessed is False
    assert [m.status for m in r.modules] == ["completed", "skipped", "skipped", "skipped", "skipped"]
    assert "NXDOMAIN" in r.limitations[0]


def test_input_is_normalized_and_validated():
    r = scanner(good_domain()).scan("  EXAMPLE.com. ")
    assert r.domain == D


@pytest.mark.parametrize("bad", ["http://example.com", "127.0.0.1", "localhost", "", "a b.com"])
def test_invalid_domains_are_rejected_before_any_dns_query(bad):
    created = []

    def factory():
        created.append(1)
        return FakeResolver({})

    with pytest.raises(DomainValidationError):
        Scanner(resolver_factory=factory).scan(bad)
    assert created == []


def test_progress_events_are_emitted_in_order():
    events = []
    scanner(good_domain()).scan(D, progress=events.append)
    assert len(events) == 10
    assert [(e.module, e.phase) for e in events] == [
        (name, phase) for name in MODULE_ORDER for phase in ("start", "done")
    ]
    assert all(e.total == 5 for e in events)
    assert [e.index for e in events if e.phase == "start"] == [1, 2, 3, 4, 5]
    assert all(e.status == "completed" for e in events if e.phase == "done")


def test_a_crashing_module_does_not_stop_the_scan():
    class Boom(BaseModule):
        name = "boom"

        def run(self, ctx):
            raise RuntimeError("fallo simulado")

    r = scanner(good_domain(), modules=[DnsAnalysisModule(), Boom(), SpfAnalysisModule()]).scan(D)
    assert [m.status for m in r.modules] == ["completed", "error", "completed"]
    assert "SYS-001" in ids(r) and "SPF-100" in ids(r)
    assert r.risk.partial is True


def test_custom_dkim_selectors_are_used():
    holder = {}

    def factory():
        holder["resolver"] = FakeResolver(bare_domain())
        return holder["resolver"]

    Scanner(resolver_factory=factory, dkim_selectors=["foo", "bar"]).scan(D)
    queried = [name for name, _ in holder["resolver"].calls]
    assert f"foo._domainkey.{D}" in queried and f"bar._domainkey.{D}" in queried
    assert f"google._domainkey.{D}" not in queried


def test_build_default_modules_order_and_selectors():
    modules = build_default_modules(["a1"])
    assert [m.name for m in modules] == MODULE_ORDER
    assert next(m for m in modules if isinstance(m, DkimAnalysisModule)).selectors == ["a1"]


def test_timestamps_and_duration_use_injected_clock():
    t0 = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
    times = iter([t0, t0 + timedelta(seconds=2.5)])
    r = scanner(good_domain(), now=lambda: next(times)).scan(D)
    assert r.started_at == t0 and r.duration_seconds == 2.5


def test_result_metadata_and_snapshot():
    r = scanner(good_domain()).scan(D)
    assert r.tool_version == __version__
    assert r.dns_records["A"] == ["93.184.216.34"]
    assert "NS" in r.dns_records and "MX" not in r.dns_records
    assert "autorización" in r.authorization_notice
    assert any("DKIM" in text for text in r.limitations)
    assert all(m.duration_ms >= 0 for m in r.modules)
    assert sum(m.findings_count for m in r.modules) == len(r.findings)


def test_dns_timeouts_make_the_score_provisional():
    answers = bare_domain()
    answers[(D, "TXT")] = status(D, "TXT", "timeout")
    r = scanner(answers).scan(D)
    assert r.risk.partial is True