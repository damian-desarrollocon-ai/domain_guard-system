from domainguard.models.findings import Severity
from domainguard.modules.base import BaseModule, ScanContext, run_safely
from domainguard.modules.dns_analysis import DnsAnalysisModule

from .helpers import FakeResolver, ok, status

D = "example.com"


def _run(answers):
    resolver = FakeResolver(answers)
    ctx = ScanContext(domain=D, resolver=resolver)
    return DnsAnalysisModule().run(ctx), ctx, resolver


def _ids(findings):
    return {f.id for f in findings}


def test_healthy_domain_has_no_findings():
    findings, ctx, _ = _run(
        {
            (D, "A"): ok(D, "A", "93.184.216.34"),
            (D, "NS"): ok(D, "NS", "ns1.example.net.", "ns2.example.net."),
            (D, "SOA"): ok(D, "SOA", "ns1.example.net. admin.example.net. 1 3600 600 86400 300"),
        }
    )
    assert findings == []
    assert ctx.data["domain_exists"] is True
    assert "NS" in ctx.data["dns"]


def test_nxdomain_stops_early():
    findings, ctx, resolver = _run({(D, "A"): status(D, "A", "nxdomain")})
    assert _ids(findings) == {"DNS-001"}
    assert findings[0].severity == Severity.INFORMATIONAL
    assert ctx.data["domain_exists"] is False
    assert resolver.calls == [(D, "A")]


def test_single_ns_is_potential_low_risk():
    findings, _, _ = _run(
        {(D, "A"): ok(D, "A", "1.2.3.4"), (D, "NS"): ok(D, "NS", "ns1.example.net.")}
    )
    assert _ids(findings) == {"DNS-003"}
    assert findings[0].severity == Severity.LOW


def test_timeout_does_not_claim_anything_about_that_record():
    findings, _, _ = _run(
        {(D, "A"): ok(D, "A", "1.2.3.4"), (D, "NS"): status(D, "NS", "timeout")}
    )
    assert _ids(findings) == {"DNS-002"}


def test_no_address_records_is_informational():
    findings, _, _ = _run(
        {(D, "NS"): ok(D, "NS", "ns1.example.net.", "ns2.example.net.")}
    )
    assert _ids(findings) == {"DNS-004"}
    assert findings[0].severity == Severity.INFORMATIONAL


def test_run_safely_isolates_module_errors():
    class Boom(BaseModule):
        name = "boom"

        def run(self, ctx):
            raise RuntimeError("fallo simulado")

    findings = run_safely(Boom(), ScanContext(domain=D, resolver=FakeResolver()))
    assert _ids(findings) == {"SYS-001"}
    assert "fallo simulado" in findings[0].evidence[0]