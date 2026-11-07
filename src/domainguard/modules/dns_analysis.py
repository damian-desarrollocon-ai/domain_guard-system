"""Recolección y análisis básico de registros DNS del dominio."""
from __future__ import annotations

from domainguard.core.resolver import DnsAnswer
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

from .base import BaseModule, ScanContext

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA")
FAILED_STATUSES = {"timeout", "servfail", "error"}


def _evidence(answer: DnsAnswer) -> str:
    if answer.records:
        return f"{answer.rdtype}: " + "; ".join(answer.records)
    return f"{answer.rdtype}: sin registros (estado: {answer.status})"


class DnsAnalysisModule(BaseModule):
    name = "dns_analysis"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        answers: dict[str, DnsAnswer] = {}
        ctx.data["domain_exists"] = True

        for rdtype in RECORD_TYPES:
            answer = ctx.resolver.query(ctx.domain, rdtype)
            answers[rdtype] = answer
            if answer.status == "nxdomain":
                ctx.data["domain_exists"] = False
                findings.append(self._nxdomain(ctx.domain, answer))
                break

        ctx.data["dns"] = answers
        if not ctx.data["domain_exists"]:
            return findings

        failed = [a for a in answers.values() if a.status in FAILED_STATUSES]
        if failed:
            findings.append(self._incomplete(failed))

        ns = answers.get("NS")
        if ns is not None and ns.status == "ok" and len(ns.records) == 1:
            findings.append(self._single_ns(ns))

        a, aaaa = answers.get("A"), answers.get("AAAA")
        if a and aaaa and a.status == "no_data" and aaaa.status == "no_data":
            findings.append(self._no_address(a, aaaa))

        return findings

    def _nxdomain(self, domain: str, answer: DnsAnswer) -> Finding:
        return Finding(
            id="DNS-001",
            module=self.name,
            title="El dominio no existe en DNS (NXDOMAIN)",
            description=f"Los servidores DNS indicaron que '{domain}' no existe.",
            evidence=[f"{answer.rdtype} {domain}: NXDOMAIN"],
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.CONFIRMED,
            technical_explanation=(
                "La respuesta NXDOMAIN indica que el nombre no está delegado ni definido. "
                "Se omitieron los demás módulos que dependen de registros existentes."
            ),
            business_impact="Si el dominio debería estar activo, ni su web ni su correo funcionarán.",
            remediation="Verificar que el nombre esté bien escrito, registrado y delegado a servidores DNS activos.",
            confidence=Confidence.HIGH,
            validation_limitations="Un resolver con problemas podría responder erróneamente; repetir el escaneo para confirmar.",
        )

    def _incomplete(self, failed: list[DnsAnswer]) -> Finding:
        return Finding(
            id="DNS-002",
            module=self.name,
            title="Consultas DNS incompletas",
            description="Algunas consultas no obtuvieron respuesta definitiva, por lo que el análisis es parcial.",
            evidence=[f"{a.rdtype}: {a.status}" for a in failed],
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.INFORMATIONAL,
            technical_explanation=(
                "Timeouts o errores de servidor impiden afirmar si esos registros existen. "
                "No se concluye nada sobre ellos."
            ),
            business_impact="Ninguno directo; podría indicar inestabilidad de los servidores DNS autoritativos.",
            remediation="Repetir el escaneo. Si persiste, revisar la salud de los servidores DNS del dominio.",
            confidence=Confidence.MEDIUM,
            validation_limitations="Puede deberse a la red local o al resolver usado, no necesariamente al dominio.",
        )

    def _single_ns(self, answer: DnsAnswer) -> Finding:
        return Finding(
            id="DNS-003",
            module=self.name,
            title="Un solo servidor de nombres (NS) publicado",
            description="El dominio publica un único registro NS visible.",
            evidence=[_evidence(answer)],
            severity=Severity.LOW,
            category=FindingCategory.POTENTIAL_RISK,
            technical_explanation=(
                "Las buenas prácticas (RFC 2182) recomiendan al menos dos servidores autoritativos "
                "en redes distintas. Un solo NS es un punto único de falla."
            ),
            business_impact="Si ese servidor falla, el dominio puede dejar de resolver (web y correo).",
            remediation="Agregar al menos un segundo servidor de nombres, idealmente en otra red o proveedor.",
            confidence=Confidence.MEDIUM,
            validation_limitations=(
                "Solo se ve lo que responde el resolver; un único nombre NS puede estar respaldado "
                "por infraestructura anycast redundante."
            ),
        )

    def _no_address(self, a: DnsAnswer, aaaa: DnsAnswer) -> Finding:
        return Finding(
            id="DNS-004",
            module=self.name,
            title="Sin registros A ni AAAA en el dominio",
            description="El dominio no resuelve a ninguna dirección IP.",
            evidence=[_evidence(a), _evidence(aaaa)],
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.INFORMATIONAL,
            technical_explanation=(
                "Es común en dominios usados solo para correo o como zona delegada. "
                "Los módulos web se limitarán a lo que sea alcanzable."
            ),
            business_impact="Ninguno si el dominio no se usa como sitio web.",
            remediation="Ninguna requerida si es intencional.",
            confidence=Confidence.HIGH,
            validation_limitations="Solo se consultó el nombre exacto indicado.",
        )