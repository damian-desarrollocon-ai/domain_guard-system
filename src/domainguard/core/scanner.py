"""Orquestador: valida el dominio, ejecuta los módulos en orden y calcula el riesgo."""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from domainguard import __version__
from domainguard.config import DEFAULT_RISK_CONFIG, RiskConfig
from domainguard.core.resolver import DnsResolver, ResolverProtocol
from domainguard.core.risk_engine import SEVERITY_ORDER, assess
from domainguard.core.validation import validate_domain
from domainguard.models.findings import Finding
from domainguard.models.scan_result import ModuleRun, ScanResult
from domainguard.modules.base import BaseModule, ScanContext, run_safely
from domainguard.modules.dkim_analysis import DkimAnalysisModule
from domainguard.modules.dmarc_analysis import DmarcAnalysisModule
from domainguard.modules.dns_analysis import DnsAnalysisModule
from domainguard.modules.spf_analysis import SpfAnalysisModule
from domainguard.modules.spoofing_analysis import SpoofingAnalysisModule

AUTHORIZATION_NOTICE = (
    "DomainGuard realiza únicamente evaluaciones pasivas de información pública. Cualquier prueba "
    "activa requiere autorización explícita y por escrito del propietario del dominio, y esta "
    "herramienta no las realiza."
)

GENERAL_LIMITATIONS = (
    "Evaluación pasiva basada en información pública (DNS); no accede a sistemas ni a buzones del dominio.",
    "No prueba que un correo falsificado sea aceptado o rechazado: el resultado real depende de cada receptor.",
    "DKIM solo se comprueba para los selectores consultados; un selector no encontrado no prueba que DKIM esté ausente.",
    "Los resultados reflejan un momento concreto y el resolver DNS utilizado; pueden variar al repetir el escaneo.",
    "La puntuación resume la configuración pública analizada; no mide la seguridad total de la organización.",
)


@dataclass(frozen=True)
class ProgressEvent:
    module: str
    index: int            # posición, empezando en 1
    total: int
    phase: str            # "start" o "done"
    status: str | None = None   # solo en "done": completed, skipped o error


def build_default_modules(dkim_selectors: Iterable[str] | None = None) -> list[BaseModule]:
    """Orden importante: DNS primero y el análisis de spoofing al final (lee a los demás)."""
    return [
        DnsAnalysisModule(),
        SpfAnalysisModule(),
        DkimAnalysisModule(dkim_selectors),
        DmarcAnalysisModule(),
        SpoofingAnalysisModule(),
    ]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Scanner:
    def __init__(
        self,
        modules: Sequence[BaseModule] | None = None,
        *,
        dkim_selectors: Iterable[str] | None = None,
        resolver_factory: Callable[[], ResolverProtocol] | None = None,
        risk_config: RiskConfig | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._modules = list(modules) if modules is not None else build_default_modules(dkim_selectors)
        self._resolver_factory = resolver_factory or DnsResolver
        self._risk_config = risk_config or DEFAULT_RISK_CONFIG
        self._now = now or _utc_now

    def scan(
        self,
        raw_domain: str,
        progress: Callable[[ProgressEvent], None] | None = None,
    ) -> ScanResult:
        domain = validate_domain(raw_domain)      # lanza DomainValidationError si no es válido
        resolver = self._resolver_factory()
        ctx = ScanContext(domain=domain, resolver=resolver)

        def emit(module: str, index: int, phase: str, status: str | None = None) -> None:
            if progress is not None:
                progress(ProgressEvent(module, index, len(self._modules), phase, status))

        started = self._now()
        runs: list[ModuleRun] = []
        findings: list[Finding] = []

        for index, module in enumerate(self._modules, start=1):
            emit(module.name, index, "start")
            t0 = time.perf_counter()
            if ctx.data.get("domain_exists") is False:
                status, found = "skipped", []
            else:
                found = run_safely(module, ctx)
                status = "error" if any(f.id == "SYS-001" for f in found) else "completed"
            duration_ms = int((time.perf_counter() - t0) * 1000)
            runs.append(ModuleRun(
                name=module.name, status=status, findings_count=len(found), duration_ms=duration_ms,
            ))
            findings.extend(found)
            emit(module.name, index, "done", status)

        finished = self._now()
        severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        findings.sort(key=lambda f: (severity_rank[f.severity], f.id))

        assessed = ctx.data.get("domain_exists") is not False
        limitations = list(GENERAL_LIMITATIONS)
        if not assessed:
            limitations.insert(
                0,
                "El dominio no existe en DNS (NXDOMAIN): no hay configuración que evaluar y la "
                "puntuación no es significativa.",
            )

        dns_records = {
            rdtype: list(answer.records)
            for rdtype, answer in ctx.data.get("dns", {}).items()
            if answer.records
        }

        return ScanResult(
            tool_version=__version__,
            domain=domain,
            started_at=started,
            finished_at=finished,
            duration_seconds=round((finished - started).total_seconds(), 3),
            assessed=assessed,
            modules=runs,
            findings=findings,
            risk=assess(findings, self._risk_config),
            dns_queries=getattr(resolver, "queries_made", None),
            dns_records=dns_records,
            authorization_notice=AUTHORIZATION_NOTICE,
            limitations=limitations,
        )