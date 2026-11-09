"""Resultado completo de un escaneo (lo que se serializa a JSON y alimenta los reportes)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from domainguard.models.findings import Finding
from domainguard.models.risk import RiskAssessment

ModuleStatus = Literal["completed", "skipped", "error"]


class ModuleRun(BaseModel):
    name: str
    status: ModuleStatus
    findings_count: int
    duration_ms: int


class ScanResult(BaseModel):
    tool_version: str
    domain: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    assessed: bool = True    # False si el dominio no existe: la puntuación no es significativa
    modules: list[ModuleRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment
    dns_queries: int | None = None
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    authorization_notice: str
    limitations: list[str] = Field(default_factory=list)