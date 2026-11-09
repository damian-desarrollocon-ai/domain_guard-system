from datetime import datetime, timezone

from domainguard.core.report_generator import executive_summary, render_html, write_html
from domainguard.core.scanner import Scanner

from .helpers import FakeResolver, ok, status
from .test_dkim_parse import REAL_RSA_2048

D = "example.com"


def scan(answers):
    return Scanner(resolver_factory=lambda: FakeResolver(answers)).scan(D)


def bare():
    return {(D, "A"): ok(D, "A", "93.184.216.34"), (D, "NS"): ok(D, "NS", "ns1.x.net.", "ns2.x.net.")}


def good():
    answers = bare()
    answers[(D, "TXT")] = ok(D, "TXT", "v=spf1 ip4:192.0.2.0/24 -all")
    answers[(f"google._domainkey.{D}", "TXT")] = ok("x", "TXT", f"v=DKIM1; k=rsa; p={REAL_RSA_2048}")
    answers[(f"_dmarc.{D}", "TXT")] = ok("x", "TXT", "v=DMARC1; p=reject; rua=mailto:r@example.com")
    return answers


def test_report_basic_structure_and_language():
    html = render_html(scan(bare()))
    assert html.startswith("<!DOCTYPE html>") and '<html lang="es">' in html
    assert "example.com" in html and "Resumen ejecutivo" in html
    for section in ("Módulos ejecutados", "Hallazgos", "Cómo se calculó la puntuación",
                    "Registros DNS observados", "Limitaciones de la evaluación"):
        assert section in html


def test_report_shows_score_grade_and_findings():
    result = scan(bare())
    html = render_html(result)
    assert 'class="num">69<' in html and "grade-C" in html and "Regular" in html
    for finding in result.findings:
        assert finding.id in html and finding.title in html


def test_report_groups_findings_by_severity_with_spanish_labels():
    html = render_html(scan(bare()))
    assert "Alta (1)" in html and "Media (2)" in html and "Informativa (1)" in html
    assert "Crítica (" not in html          # grupos vacíos no se muestran
    assert "Riesgo potencial" in html and "Confirmado" in html
    assert html.index("Alta (1)") < html.index("Media (2)") < html.index("Informativa (1)")


def test_every_finding_shows_all_required_sections():
    html = render_html(scan(bare()))
    for label in ("Descripción", "Evidencia técnica", "Explicación técnica", "Impacto en el negocio",
                  "Remediación recomendada", "Limitaciones de validación"):
        assert label in html


def test_score_breakdown_lists_deductions_and_derived_note():
    html = render_html(scan(bare()))
    assert "Desglose de descuentos" in html
    assert "SPOOF-001" in html and "se pondera al 50%" in html
    assert "Descuento total" in html and "−" in html


def test_perfect_domain_has_no_deduction_rows():
    html = render_html(scan(good()))
    assert "Ningún hallazgo restó puntos" in html
    assert 'class="num">100<' in html and "grade-A" in html


def test_nonexistent_domain_is_marked_not_assessable():
    html = render_html(scan({(D, "A"): status(D, "A", "nxdomain")}))
    assert "Dominio no evaluable" in html and "sin evaluar" in html
    assert 'class="num">—<' in html


def test_provisional_banner_when_analysis_is_incomplete():
    answers = bare()
    answers[(D, "TXT")] = status(D, "TXT", "timeout")
    html = render_html(scan(answers))
    assert "Puntuación provisional" in html


def test_dns_records_are_listed():
    html = render_html(scan(good()))
    assert "93.184.216.34" in html and "ns1.x.net." in html


def test_hostile_dns_content_is_escaped_not_executed():
    answers = bare()
    payload = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    answers[(D, "TXT")] = ok(D, "TXT", f"v=spf1 {payload} -all")
    html = render_html(scan(answers))
    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script" not in html.lower() and "<img" not in html.lower()


def test_report_is_self_contained_with_restrictive_csp():
    html = render_html(scan(good()))
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    for forbidden in ("<link", "<script", "<img", "<iframe", "http://", "https://", "@import", "url("):
        assert forbidden not in html


def test_executive_summary_content():
    paragraphs = executive_summary(scan(bare()))
    text = " ".join(paragraphs)
    assert "69/100" in text and "4 hallazgos" in text and "no demuestra" in text
    assert "no existe" in executive_summary(scan({(D, "A"): status(D, "A", "nxdomain")}))[0]


def test_dates_are_rendered_in_utc_text():
    t = datetime(2026, 11, 8, 18, 30, 5, tzinfo=timezone.utc)
    times = iter([t, t])
    result = Scanner(resolver_factory=lambda: FakeResolver(bare()), now=lambda: next(times)).scan(D)
    assert "08/11/2026 18:30:05 UTC" in render_html(result)


def test_write_html_roundtrip_utf8(tmp_path):
    result = scan(bare())
    target = write_html(result, tmp_path / "a" / "b" / "reporte.html")
    text = target.read_text(encoding="utf-8")
    assert "Puntuación" in text and text == render_html(result)