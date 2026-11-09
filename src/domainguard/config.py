"""Configuración central de DomainGuard.

Los valores por defecto son conservadores y pasivos. Las reglas de puntuación
son configurables: se puede construir un RiskConfig con valores propios.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from domainguard.models.findings import Confidence, FindingCategory, Severity

# Selectores DKIM comunes que se consultan por defecto (configurables por el usuario).
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "selector1",
    "selector2",
    "google",
    "default",
    "mail",
    "s1",
    "s2",
    "k1",
    "dkim",
    "smtp",
)


class RiskConfig(BaseModel):
    """Reglas del motor de puntuación (todas modificables).

    descuento = puntos_por_severidad x factor_confianza x factor_categoria x factor_derivado
    """

    severity_points: dict[Severity, float] = Field(
        default_factory=lambda: {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 22.0,
            Severity.MEDIUM: 12.0,
            Severity.LOW: 4.0,
            Severity.INFORMATIONAL: 0.0,
        }
    )
    confidence_factor: dict[Confidence, float] = Field(
        default_factory=lambda: {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.8,
            Confidence.LOW: 0.5,
        }
    )
    # Los hallazgos informativos o que solo requieren validación no descuentan puntos.
    category_factor: dict[FindingCategory, float] = Field(
        default_factory=lambda: {
            FindingCategory.CONFIRMED: 1.0,
            FindingCategory.POTENTIAL_RISK: 0.7,
            FindingCategory.INFORMATIONAL: 0.0,
            FindingCategory.REQUIRES_VALIDATION: 0.0,
        }
    )
    # Hallazgos que resumen problemas ya puntuados por separado: se ponderan para no contar doble.
    derived_factors: dict[str, float] = Field(default_factory=lambda: {"SPOOF-001": 0.5})
    # Descuento máximo que puede aportar un solo módulo.
    module_deduction_cap: float = 45.0
    # Con un hallazgo de esta severidad (que descuente puntos) la nota no puede superar este techo.
    score_ceilings: dict[Severity, int] = Field(
        default_factory=lambda: {Severity.CRITICAL: 49, Severity.HIGH: 69, Severity.MEDIUM: 89}
    )
    # (puntaje mínimo, letra, calificación), de mayor a menor.
    rating_bands: list[tuple[int, str, str]] = Field(
        default_factory=lambda: [
            (90, "A", "Excelente"),
            (75, "B", "Buena"),
            (60, "C", "Regular"),
            (40, "D", "Deficiente"),
            (0, "F", "Crítica"),
        ]
    )
    # Hallazgos que indican análisis incompleto: la puntuación se marca como provisional.
    incomplete_ids: set[str] = Field(
        default_factory=lambda: {
            "SYS-001", "DNS-002", "SPF-013", "DKIM-008", "DMARC-013", "SPOOF-002",
        }
    )


DEFAULT_RISK_CONFIG = RiskConfig()