"""Modelos del resultado de puntuación de riesgo."""
from __future__ import annotations

from pydantic import BaseModel, Field

from domainguard.models.findings import Confidence, FindingCategory, Severity


class ScoreLine(BaseModel):
    """Cómo contribuyó un hallazgo a la puntuación."""

    finding_id: str
    module: str
    title: str
    severity: Severity
    category: FindingCategory
    confidence: Confidence
    base_points: float
    confidence_factor: float
    category_factor: float
    derived_factor: float
    raw_deduction: float        # antes del tope por módulo
    applied_deduction: float    # descuento final


class RiskAssessment(BaseModel):
    score: int                                   # 0 a 100 (100 = sin hallazgos que descuenten)
    grade: str
    rating: str
    total_deduction: float
    score_before_ceiling: int
    ceiling_applied: str | None = None           # severidad que fijó el techo, si aplicó
    partial: bool = False                        # análisis incompleto: puntuación provisional
    partial_reasons: list[str] = Field(default_factory=list)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    counts_by_category: dict[str, int] = Field(default_factory=dict)
    module_deductions: dict[str, float] = Field(default_factory=dict)
    lines: list[ScoreLine] = Field(default_factory=list)
    method: list[str] = Field(default_factory=list)   # reglas generales del cálculo
    notes: list[str] = Field(default_factory=list)    # lo que ocurrió en este escaneo