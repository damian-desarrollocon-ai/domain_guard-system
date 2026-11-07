"""Análisis de DKIM mediante consulta pasiva de selectores en DNS público.

Un selector que no existe NO prueba que el dominio no use DKIM: el selector real
solo se conoce leyendo el encabezado DKIM-Signature de un correo auténtico.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from domainguard.config import DEFAULT_DKIM_SELECTORS
from domainguard.core.dkim_parse import (
    DkimTags,
    KeyInfo,
    analyze_key,
    looks_like_dkim,
    parse_tags,
)
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

from .base import BaseModule, ScanContext

FAILED_STATUSES = {"timeout", "servfail", "error"}
MIN_RSA_BITS = 1024         # RFC 8301: por debajo no se considera válido
RECOMMENDED_RSA_BITS = 2048

_SELECTOR_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]{0,100}[a-z0-9_])?$")

DKIM_LIMITS = (
    "Solo se consultaron los selectores indicados; un selector no encontrado no prueba que "
    "DKIM esté ausente. El selector real figura en el encabezado DKIM-Signature (campo s=) de "
    "un correo auténtico del dominio, y confirmarlo requiere acceso autorizado a esos mensajes. "
    "Este análisis no verifica firmas ni comprueba si el servidor de correo firma realmente."
)


@dataclass
class _Entry:
    selector: str
    name: str
    record: str
    parsed: DkimTags
    key: KeyInfo

    @property
    def testing(self) -> bool:
        return "y" in self.parsed.tags.get("t", "").lower().split(":")

    @property
    def problems(self) -> list[str]:
        found = list(self.parsed.errors)
        if self.key.error:
            found.append(self.key.error)
        return found


def _short(text: str, limit: int = 140) -> str:
    return text if len(text) <= limit else text[:limit] + "… (truncado)"


class DkimAnalysisModule(BaseModule):
    name = "dkim_analysis"

    def __init__(self, selectors: Iterable[str] | None = None) -> None:
        raw = DEFAULT_DKIM_SELECTORS if selectors is None else selectors
        cleaned: list[str] = []
        for item in raw:
            sel = item.strip().lower()
            if not _SELECTOR_RE.match(sel) or ".." in sel:
                raise ValueError(f"Selector DKIM inválido: {item!r}")
            if sel not in cleaned:
                cleaned.append(sel)
        if not cleaned:
            raise ValueError("Se requiere al menos un selector DKIM.")
        self.selectors = cleaned

    # ------------------------------------------------------------------ run
    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.data.get("domain_exists") is False:
            return []

        entries: list[_Entry] = []
        incomplete: list[str] = []
        for sel in self.selectors:
            qname = f"{sel}._domainkey.{ctx.domain}"
            answer = ctx.resolver.query(qname, "TXT")
            if answer.status in FAILED_STATUSES:
                incomplete.append(f"{qname}: {answer.status}")
                continue
            if not answer.exists:
                continue
            for record in answer.records:
                if not looks_like_dkim(record):
                    continue
                parsed = parse_tags(record)
                entries.append(_Entry(sel, qname, record, parsed, analyze_key(parsed.tags)))

        valid = [e for e in entries if e.key.valid and not e.parsed.errors]
        invalid = [e for e in entries if e.problems]
        revoked = [e for e in entries if e.key.revoked]
        testing = [e for e in valid if e.testing]
        rsa_bits = [e.key.bits for e in valid if e.key.key_type == "rsa" and e.key.bits]

        ctx.data["dkim"] = {
            "selectors_checked": list(self.selectors),
            "found": sorted({e.selector for e in entries}),
            "valid": sorted({e.selector for e in valid}),
            "invalid": sorted({e.selector for e in invalid}),
            "revoked": sorted({e.selector for e in revoked}),
            "testing": sorted({e.selector for e in testing}),
            "incomplete": bool(incomplete),
            "min_rsa_bits": min(rsa_bits) if rsa_bits else None,
        }

        findings: list[Finding] = []

        if not entries:
            if incomplete:
                return [self._incomplete(incomplete)]
            findings.append(self._none_found(ctx.domain))
            return findings

        if invalid:
            findings.append(self._f(
                "DKIM-003", "Registros DKIM con errores",
                description="Se encontraron registros de clave DKIM que no cumplen el formato esperado.",
                evidence=[
                    line
                    for e in invalid
                    for line in (f"{e.name}: {_short(e.record)}", *[f"  - {p}" for p in e.problems])
                ],
                severity=Severity.LOW if valid else Severity.MEDIUM,
                category=FindingCategory.CONFIRMED,
                technical=(
                    "Un receptor que no pueda leer la clave pública no puede verificar firmas hechas "
                    "con ese selector, por lo que fallarán DKIM."
                ),
                impact=(
                    "Si el selector está en uso, los correos legítimos pueden fallar DKIM; si es un "
                    "registro olvidado, no tiene efecto."
                ),
                remediation="Corregir el registro con los datos del proveedor de correo, o eliminarlo si el selector ya no se usa.",
                confidence=Confidence.HIGH,
                limitations=DKIM_LIMITS + " No se sabe si el selector con errores está en uso.",
            ))

        if revoked:
            findings.append(self._f(
                "DKIM-004", "Clave DKIM revocada (p= vacío)",
                description="Hay selectores publicados con la clave pública vacía.",
                evidence=[f"{e.name}: {_short(e.record)}" for e in revoked],
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical="Un p= vacío indica que la clave fue revocada de forma deliberada (RFC 6376). Las firmas con ese selector se consideran inválidas.",
                impact="Ninguno si la revocación es intencional.",
                remediation="Ninguna requerida; confirmar que ningún servicio legítimo siga firmando con ese selector.",
                confidence=Confidence.HIGH,
            ))

        weak = [e for e in valid if e.key.key_type == "rsa" and e.key.bits and e.key.bits < MIN_RSA_BITS]
        if weak:
            findings.append(self._f(
                "DKIM-005", "Clave DKIM RSA menor a 1024 bits",
                description="Se publican claves RSA por debajo del mínimo aceptado.",
                evidence=[f"{e.name}: RSA {e.key.bits} bits" for e in weak],
                severity=Severity.HIGH,
                category=FindingCategory.CONFIRMED,
                technical=(
                    "RFC 8301 establece que los verificadores no deben aceptar firmas con RSA menor a "
                    "1024 bits, y claves tan cortas son criptográficamente débiles. Esto describe la "
                    "configuración; no se intentó ni se afirma explotación."
                ),
                impact="Las firmas DKIM con esa clave pueden ser rechazadas por receptores modernos y la clave no ofrece protección sólida.",
                remediation="Generar un par de claves RSA de 2048 bits, publicar el nuevo selector y retirar el anterior.",
                confidence=Confidence.HIGH,
                limitations=DKIM_LIMITS + " No se sabe si el selector está en uso.",
            ))

        short = [e for e in valid if e.key.key_type == "rsa" and e.key.bits and MIN_RSA_BITS <= e.key.bits < RECOMMENDED_RSA_BITS]
        if short:
            findings.append(self._f(
                "DKIM-006", "Clave DKIM RSA por debajo de 2048 bits",
                description="Se publican claves RSA de menos de 2048 bits.",
                evidence=[f"{e.name}: RSA {e.key.bits} bits" for e in short],
                severity=Severity.LOW,
                category=FindingCategory.CONFIRMED,
                technical="1024 bits sigue siendo aceptado, pero la práctica actual recomienda 2048 bits o más.",
                impact="Margen de seguridad menor que el recomendado a largo plazo.",
                remediation="Rotar a una clave RSA de 2048 bits (algunos DNS requieren dividir el TXT en cadenas de 255 caracteres).",
                confidence=Confidence.HIGH,
                limitations=DKIM_LIMITS + " No se sabe si el selector está en uso.",
            ))

        if testing:
            findings.append(self._f(
                "DKIM-007", "Selector DKIM en modo de prueba (t=y)",
                description="Hay selectores marcados como en pruebas.",
                evidence=[f"{e.name}: {_short(e.record)}" for e in testing],
                severity=Severity.LOW,
                category=FindingCategory.CONFIRMED,
                technical="Con t=y el dominio indica que está probando DKIM; los verificadores no deben tratar esos mensajes distinto de uno sin firma.",
                impact="Mientras siga en pruebas, esa firma puede no aportar protección real.",
                remediation="Quitar t=y una vez confirmado que la firma funciona correctamente.",
                confidence=Confidence.HIGH,
                limitations=DKIM_LIMITS,
            ))

        if incomplete:
            findings.append(self._incomplete(incomplete))

        if valid:
            summary = []
            for e in valid:
                if e.key.key_type == "rsa":
                    summary.append(f"{e.name}: RSA {e.key.bits} bits")
                else:
                    summary.append(f"{e.name}: {e.key.key_type}")
            findings.append(self._f(
                "DKIM-100", "Selectores DKIM válidos encontrados",
                description=f"Se encontraron {len(valid)} registro(s) de clave DKIM con formato válido.",
                evidence=summary,
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical="Confirma que existen claves públicas publicadas; no prueba que el servidor de correo las use para firmar.",
                impact="Ninguno por sí mismo.",
                remediation="Ninguna requerida.",
                confidence=Confidence.HIGH,
                limitations=DKIM_LIMITS,
            ))
        return findings

    # --------------------------------------------------------------- helpers
    def _f(
        self,
        fid: str,
        title: str,
        *,
        description: str,
        evidence: list[str],
        severity: Severity,
        category: FindingCategory,
        technical: str,
        impact: str,
        remediation: str,
        confidence: Confidence,
        limitations: str = DKIM_LIMITS,
    ) -> Finding:
        return Finding(
            id=fid, module=self.name, title=title, description=description,
            evidence=evidence, severity=severity, category=category,
            technical_explanation=technical, business_impact=impact,
            remediation=remediation, confidence=confidence,
            validation_limitations=limitations,
        )

    def _none_found(self, domain: str) -> Finding:
        return self._f(
            "DKIM-001", "No se encontraron registros DKIM en los selectores comprobados",
            description=f"Ninguno de los {len(self.selectors)} selectores consultados publica una clave DKIM para '{domain}'.",
            evidence=["Selectores consultados: " + ", ".join(self.selectors)],
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.REQUIRES_VALIDATION,
            technical=(
                "El dominio puede usar un selector distinto a los comunes. Esta ausencia no permite "
                "concluir que DKIM no esté configurado."
            ),
            impact=(
                "Si realmente no hay DKIM, la autenticación DMARC dependería solo de SPF. Esto no se "
                "puede confirmar desde DNS."
            ),
            remediation=(
                "Obtener el selector real de un correo auténtico (encabezado DKIM-Signature, campo s=) y "
                "volver a escanear con --dkim-selectors, o consultar al proveedor de correo."
            ),
            confidence=Confidence.LOW,
        )

    def _incomplete(self, evidence: list[str]) -> Finding:
        return self._f(
            "DKIM-008", "Consultas DKIM incompletas",
            description="Algunas consultas de selectores no obtuvieron respuesta definitiva.",
            evidence=evidence,
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.INFORMATIONAL,
            technical="Timeouts o errores de servidor impiden afirmar si esos selectores existen. No se concluye nada sobre ellos.",
            impact="Ninguno directo; el análisis DKIM es parcial.",
            remediation="Repetir el escaneo. Si persiste, revisar los servidores DNS del dominio.",
            confidence=Confidence.MEDIUM,
        )