"""Modelos de hallazgos: contrato común entre módulos, scoring y reportes."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingCategory(str, Enum):
    CONFIRMED = "confirmed"                      # configuración observada directamente
    POTENTIAL_RISK = "potential_risk"            # riesgo que depende de contexto
    INFORMATIONAL = "informational"              # observación sin riesgo directo
    REQUIRES_VALIDATION = "requires_authorized_validation"  # solo verificable con autorización


class Finding(BaseModel):
    id: str = Field(description="Identificador estable, p. ej. SPF-001")
    module: str
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    severity: Severity
    category: FindingCategory
    technical_explanation: str
    business_impact: str
    remediation: str
    confidence: Confidence
    validation_limitations: str