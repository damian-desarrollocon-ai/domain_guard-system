from domainguard.core.report_generator import counts_sentence, executive_summary
from domainguard.core.scanner import Scanner

from .helpers import FakeResolver, ok

D = "example.com"


def counts(**kw):
    base = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    base.update(kw)
    return base


def test_singular_forms():
    assert counts_sentence(counts(MEDIUM=1)) == (
        "Se registró 1 hallazgo: 0 críticos, 0 altos, 1 medio, 0 bajos y 0 informativos."
    )


def test_plural_forms():
    assert counts_sentence(counts(CRITICAL=2, HIGH=1, MEDIUM=3, LOW=1, INFORMATIONAL=7)) == (
        "Se registraron 14 hallazgos: 2 críticos, 1 alto, 3 medios, 1 bajo y 7 informativos."
    )


def test_summary_uses_the_sentence():
    answers = {(D, "A"): ok(D, "A", "1.2.3.4"), (D, "NS"): ok(D, "NS", "ns1.x.net.", "ns2.x.net.")}
    result = Scanner(resolver_factory=lambda: FakeResolver(answers)).scan(D)
    text = " ".join(executive_summary(result))
    assert "Se registraron 4 hallazgos: 0 críticos, 1 alto, 2 medios, 0 bajos y 1 informativo." in text