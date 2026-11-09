"""Motor de puntuación de riesgo: transparente, configurable y explicable.

La puntuación resume hallazgos de configuración pública; no mide la seguridad
total de la organización ni prueba que un ataque sea posible.
"""
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable

from domainguard.config import DEFAULT_RISK_CONFIG, RiskConfig
from domainguard.models.findings import Finding, FindingCategory, Severity
from domainguard.models.risk import RiskAssessment, ScoreLine

SEVERITY_ORDER = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL,
)


def rating_for(score: int, config: RiskConfig | None = None) -> tuple[str, str]:
    """Devuelve (letra, calificación) para una puntuación."""
    cfg = config or DEFAULT_RISK_CONFIG
    for minimum, grade, label in sorted(cfg.rating_bands, key=lambda b: b[0], reverse=True):
        if score >= minimum:
            return grade, label
    return cfg.rating_bands[-1][1], cfg.rating_bands[-1][2]


def describe_method(config: RiskConfig | None = None) -> list[str]:
    """Texto estático que explica cómo se calcula la puntuación (para el reporte)."""
    cfg = config or DEFAULT_RISK_CONFIG
    points = ", ".join(
        f"{s.value} {cfg.severity_points.get(s, 0):g}" for s in SEVERITY_ORDER
    )
    conf = ", ".join(f"{c.value} x{f:g}" for c, f in cfg.confidence_factor.items())
    cats = ", ".join(f"{c.value} x{f:g}" for c, f in cfg.category_factor.items())
    ceilings = ", ".join(
        f"{s.value} → máximo {cfg.score_ceilings[s]}"
        for s in SEVERITY_ORDER if s in cfg.score_ceilings
    )
    bands = ", ".join(f"{g} ({label}) desde {m}" for m, g, label in cfg.rating_bands)
    return [
        "La puntuación parte de 100 y resta puntos por cada hallazgo.",
        f"Puntos base por severidad: {points}.",
        f"Se multiplican por la confianza del hallazgo ({conf}) y por su categoría ({cats}).",
        "Los hallazgos informativos o que solo requieren validación autorizada no restan puntos.",
        "Un hallazgo que resume problemas ya puntuados (p. ej. la evaluación combinada de "
        "suplantación) se pondera con un factor menor para no contarlos dos veces.",
        f"Ningún módulo puede restar más de {cfg.module_deduction_cap:g} puntos.",
        f"Techos de nota si existe al menos un hallazgo que reste puntos: {ceilings}.",
        f"Calificación: {bands}.",
        "La puntuación resume la configuración pública analizada; no mide la seguridad total "
        "de la organización ni demuestra que un ataque sea posible.",
    ]


def assess(findings: Iterable[Finding], config: RiskConfig | None = None) -> RiskAssessment:
    cfg = config or DEFAULT_RISK_CONFIG
    items = list(findings)

    # 1) descuento bruto por hallazgo
    raw: list[tuple[Finding, float, float, float, float, float]] = []
    for f in items:
        base = cfg.severity_points.get(f.severity, 0.0)
        conf = cfg.confidence_factor.get(f.confidence, 1.0)
        cat = cfg.category_factor.get(f.category, 0.0)
        derived = cfg.derived_factors.get(f.id, 1.0)
        raw.append((f, base, conf, cat, derived, base * conf * cat * derived))

    # 2) tope por módulo (se reparte proporcionalmente)
    module_raw: dict[str, float] = defaultdict(float)
    for f, *_, deduction in raw:
        module_raw[f.module] += deduction
    capped_modules = sorted(m for m, total in module_raw.items() if total > cfg.module_deduction_cap)

    lines: list[ScoreLine] = []
    module_applied: dict[str, float] = defaultdict(float)
    for f, base, conf, cat, derived, deduction in raw:
        total = module_raw[f.module]
        applied = deduction * (cfg.module_deduction_cap / total) if total > cfg.module_deduction_cap else deduction
        module_applied[f.module] += applied
        lines.append(ScoreLine(
            finding_id=f.id, module=f.module, title=f.title, severity=f.severity,
            category=f.category, confidence=f.confidence, base_points=base,
            confidence_factor=conf, category_factor=cat, derived_factor=derived,
            raw_deduction=round(deduction, 2), applied_deduction=round(applied, 2),
        ))

    total_deduction = round(sum(line.applied_deduction for line in lines), 2)
    before_ceiling = max(0, min(100, math.floor(100 - total_deduction + 0.5)))

    # 3) techos por severidad
    score, ceiling_applied = before_ceiling, None
    for severity in SEVERITY_ORDER:
        ceiling = cfg.score_ceilings.get(severity)
        if ceiling is None:
            continue
        if any(l.severity == severity and l.applied_deduction > 0 for l in lines) and score > ceiling:
            score, ceiling_applied = ceiling, severity.value

    grade, rating = rating_for(score, cfg)
    partial_reasons = [f"{f.id}: {f.title}" for f in items if f.id in cfg.incomplete_ids]

    notes: list[str] = []
    for line in lines:
        if line.derived_factor != 1.0 and line.raw_deduction > 0:
            notes.append(
                f"{line.finding_id} se pondera al {line.derived_factor * 100:g}% porque resume "
                "problemas ya puntuados individualmente."
            )
    for module in capped_modules:
        notes.append(
            f"El módulo {module} alcanzó el tope de {cfg.module_deduction_cap:g} puntos de descuento."
        )
    if ceiling_applied:
        notes.append(
            f"La nota se limitó a {score} (techo por hallazgo de severidad {ceiling_applied}); "
            f"sin techo habría sido {before_ceiling}."
        )
    if partial_reasons:
        notes.append(
            "El análisis quedó incompleto en algunas áreas; la puntuación es provisional y podría cambiar al repetir el escaneo."
        )
    if total_deduction == 0:
        notes.append("No se detectaron hallazgos que resten puntos.")

    return RiskAssessment(
        score=score, grade=grade, rating=rating, total_deduction=total_deduction,
        score_before_ceiling=before_ceiling, ceiling_applied=ceiling_applied,
        partial=bool(partial_reasons), partial_reasons=partial_reasons,
        counts_by_severity={s.value: sum(1 for f in items if f.severity == s) for s in SEVERITY_ORDER},
        counts_by_category={c.value: sum(1 for f in items if f.category == c) for c in FindingCategory},
        module_deductions={m: round(v, 2) for m, v in sorted(module_applied.items())},
        lines=lines, method=describe_method(cfg), notes=notes,
    )