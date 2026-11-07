"""Contrato común de los módulos de análisis."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from domainguard.core.resolver import QueryLimitExceeded, ResolverProtocol
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)


@dataclass
class ScanContext:
    """Estado compartido de un escaneo.

    `data` permite que un módulo reutilice resultados de otro (p. ej. SPF y
    DMARC leen los TXT ya consultados) sin repetir consultas DNS.
    """

    domain: str
    resolver: ResolverProtocol
    data: dict[str, Any] = field(default_factory=dict)


class BaseModule(ABC):
    name: ClassVar[str]

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]:
        """Ejecuta el análisis y devuelve hallazgos."""


def _system_finding(module: str, title: str, detail: str) -> Finding:
    return Finding(
        id="SYS-001",
        module=module,
        title=title,
        description=(
            f"El módulo '{module}' no pudo completarse, por lo que sus "
            "resultados están incompletos."
        ),
        evidence=[detail],
        severity=Severity.INFORMATIONAL,
        category=FindingCategory.INFORMATIONAL,
        technical_explanation=(
            "Ocurrió una condición inesperada durante el análisis. La ausencia "
            "de hallazgos de este módulo no debe interpretarse como ausencia de problemas."
        ),
        business_impact="Ninguno directo; la evaluación de esta área es parcial.",
        remediation="Repetir el escaneo. Si persiste, revisar conectividad y registros del programa.",
        confidence=Confidence.HIGH,
        validation_limitations="No se obtuvieron datos suficientes para evaluar este módulo.",
    )


def run_safely(module: BaseModule, ctx: ScanContext) -> list[Finding]:
    """Ejecuta un módulo sin que un fallo detenga todo el escaneo."""
    try:
        return module.run(ctx)
    except QueryLimitExceeded as exc:
        return [_system_finding(module.name, "Límite de consultas DNS alcanzado", str(exc))]
    except Exception as exc:  # noqa: BLE001 - aislamiento deliberado por módulo
        return [
            _system_finding(
                module.name, "Error interno en módulo", f"{type(exc).__name__}: {exc}"
            )
        ]