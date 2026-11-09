"""Generación de reportes: JSON y HTML autocontenido (sin recursos externos)."""
from __future__ import annotations

import json
import re
from datetime import timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from domainguard.core.risk_engine import SEVERITY_ORDER
from domainguard.models.scan_result import ScanResult

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "reports" / "templates"

LABELS = {
    "severity": {
        "CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media",
        "LOW": "Baja", "INFORMATIONAL": "Informativa",
    },
    "category": {
        "confirmed": "Confirmado",
        "potential_risk": "Riesgo potencial",
        "informational": "Informativo",
        "requires_authorized_validation": "Requiere validación autorizada",
    },
    "confidence": {"HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"},
    "module_status": {"completed": "Completado", "skipped": "Omitido", "error": "Con error"},
}


def _environment() -> Environment:
    # autoescape activo: los registros DNS son texto controlado por terceros y nunca debe ejecutarse como HTML.
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"], default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _utc_text(moment) -> str:
    return moment.astimezone(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")


def executive_summary(result: ScanResult) -> list[str]:
    """Párrafos del resumen ejecutivo, derivados solo de datos del resultado."""
    if not result.assessed:
        return [
            f"No se pudo evaluar {result.domain}: el dominio no existe en DNS en el momento del análisis.",
        ]
    risk = result.risk
    c = risk.counts_by_severity
    paragraphs = [
        f"Se analizó la configuración pública de DNS y de autenticación de correo (SPF, DKIM y DMARC) de "
        f"{result.domain}. Puntuación global: {risk.score}/100 ({risk.grade}, {risk.rating}).",
        f"Se registraron {sum(c.values())} hallazgos: {c['CRITICAL']} críticos, {c['HIGH']} altos, "
        f"{c['MEDIUM']} medios, {c['LOW']} bajos y {c['INFORMATIONAL']} informativos.",
    ]
    if risk.partial:
        paragraphs.append(
            "La puntuación es provisional porque el análisis quedó incompleto en algunas áreas."
        )
    paragraphs.append(
        "Este reporte describe configuración pública; no demuestra que un ataque sea posible."
    )
    return paragraphs


def render_html(result: ScanResult) -> str:
    groups = [
        {
            "key": severity.value,
            "label": LABELS["severity"][severity.value],
            "entries": [f for f in result.findings if f.severity == severity],
        }
        for severity in SEVERITY_ORDER
        if any(f.severity == severity for f in result.findings)
    ]
    deductions = sorted(
        (line for line in result.risk.lines if line.applied_deduction > 0),
        key=lambda line: (-line.applied_deduction, line.finding_id),
    )
    template = _environment().get_template("report.html")
    return template.render(
        result=result,
        risk=result.risk,
        groups=groups,
        deductions=deductions,
        labels=LABELS,
        severity_order=[s.value for s in SEVERITY_ORDER],
        summary_paragraphs=executive_summary(result),
        started_text=_utc_text(result.started_at),
        finished_text=_utc_text(result.finished_at),
    )


def to_json(result: ScanResult) -> str:
    """Serializa el resultado completo; conserva los acentos (UTF-8)."""
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2)


def default_report_path(result: ScanResult, extension: str, base_dir: str | Path = "reports_output") -> Path:
    stamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", result.domain.lower())
    return Path(base_dir) / f"{safe_domain}_{stamp}.{extension.lstrip('.')}"


def _write_text(path: str | Path, text: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target


def write_json(result: ScanResult, path: str | Path) -> Path:
    return _write_text(path, to_json(result) + "\n")


def write_html(result: ScanResult, path: str | Path) -> Path:
    return _write_text(path, render_html(result))