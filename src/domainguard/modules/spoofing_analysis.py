"""Evaluación combinada (SPF + DKIM + DMARC) del riesgo de suplantación del dominio exacto.

Se basa solo en configuración DNS pública. No envía correos ni intenta eludir
autenticación: estima cuán probable es que los controles visibles bloqueen un
mensaje que use el dominio en el encabezado From, sin poder probarlo.
"""
from __future__ import annotations

from typing import Any

from domainguard.core.dmarc_parse import STRENGTH
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

from .base import BaseModule, ScanContext

# De menor a mayor exposición.
LEVELS = ("MINIMAL", "LIMITED", "MODERATE", "ELEVATED")
LEVEL_SEVERITY = {
    "LIMITED": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "ELEVATED": Severity.HIGH,
}
LEVEL_TEXT = {
    "LIMITED": "limitado",
    "MODERATE": "moderado",
    "ELEVATED": "elevado",
}
WEAK_DKIM_BITS = 1024

SPOOF_LIMITS = (
    "Evaluación basada únicamente en DNS: no puede probar que un mensaje falsificado real sea aceptado "
    "o rechazado, porque cada receptor aplica además su propia reputación, filtros y política. Validar "
    "el comportamiento real exigiría pruebas activas, que requieren autorización explícita del dueño "
    "del dominio y que esta herramienta no realiza (no envía correos ni suplanta a terceros). DKIM solo "
    "se conoce para los selectores consultados. Se evalúa el dominio exacto, no dominios parecidos "
    "(typosquatting) ni el nombre visible del remitente."
)


def _level_max(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def _spf_state(spf: dict[str, Any]) -> str:
    if not spf.get("present") or spf.get("multiple") or spf.get("permerror"):
        return "absent"
    return {"+": "permissive", "-": "strict", "~": "soft"}.get(spf.get("all_qualifier"), "neutral")


def _dmarc_state(dmarc: dict[str, Any]) -> str:
    if not dmarc.get("present") or not dmarc.get("valid"):
        return "absent"
    policy, pct = dmarc.get("effective_policy"), dmarc.get("pct", 100)
    if policy in ("quarantine", "reject"):
        if pct >= 100:
            return "enforced"
        return "monitor" if pct == 0 else "partial"
    return "monitor"


def _non_sending(ctx: ScanContext, spf: dict[str, Any]) -> bool:
    record = spf.get("record")
    if not record or [t.lower() for t in record.split()] != ["v=spf1", "-all"]:
        return False
    mx = ctx.data.get("dns", {}).get("MX")
    if mx is None or mx.status not in ("ok", "no_data"):
        return False
    return all(r.strip() in ("0 .", "0") for r in mx.records)


class SpoofingAnalysisModule(BaseModule):
    name = "spoofing_analysis"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.data.get("domain_exists") is False:
            return []

        spf = ctx.data.get("spf")
        dmarc = ctx.data.get("dmarc")
        dkim = ctx.data.get("dkim")

        if spf is None or dmarc is None or spf.get("present") is None or dmarc.get("present") is None:
            ctx.data["spoofing"] = {"level": "INDETERMINATE", "factors": []}
            return [self._indeterminate(spf, dmarc)]

        spf_state, dmarc_state = _spf_state(spf), _dmarc_state(dmarc)
        factors: list[str] = []
        fixes: list[str] = []

        # ---- nivel base según el estado de DMARC y SPF
        if spf_state == "permissive":
            level = "ELEVATED"
            factors.append(
                "SPF autoriza a cualquier IP (+all): un remitente con el dominio en el sobre pasaría SPF "
                "alineado y satisfaría DMARC aunque la política sea estricta."
            )
            fixes.append("Reemplazar '+all' por '-all' (o '~all' durante la transición) en el SPF.")
        elif dmarc_state in ("absent", "monitor"):
            no_spf_control = spf_state in ("absent", "neutral")
            level = "ELEVATED" if no_spf_control else "MODERATE"
            if dmarc_state == "absent":
                factors.append(
                    "No hay una política DMARC efectiva: los receptores no reciben instrucción del dueño "
                    "sobre mensajes que usan este dominio en el From."
                )
                fixes.append(
                    "Publicar DMARC (p=none con rua para empezar) y avanzar gradualmente a quarantine y reject."
                )
            else:
                factors.append(
                    "DMARC está en modo monitoreo (o con pct=0): no pide acción sobre mensajes que fallan la autenticación."
                )
                fixes.append("Revisar los reportes rua y avanzar a p=quarantine y luego p=reject con pct=100.")
            if no_spf_control:
                factors.append(
                    "SPF ausente, inválido o neutral: tampoco restringe qué servidores envían por el dominio."
                )
                fixes.append("Publicar un único SPF con los remitentes legítimos y '-all'.")
            else:
                factors.append(
                    "SPF por sí solo no protege el encabezado From: un mensaje puede pasar SPF con otro "
                    "dominio en el sobre. La protección del From depende de DMARC."
                )
        elif dmarc_state == "partial":
            level = "LIMITED"
            factors.append(
                f"DMARC se aplica solo al {dmarc.get('pct')}% de los mensajes que fallan (pct<100): el resto recibe una política más débil."
            )
            fixes.append("Subir pct a 100 cuando los reportes confirmen que los remitentes legítimos pasan.")
        else:  # enforced
            level = "MINIMAL"
            factors.append(
                f"DMARC con p={dmarc.get('effective_policy')} y pct=100: un mensaje que falle SPF y DKIM "
                "alineados debería ser tratado según esa política por los receptores que la respetan."
            )

        # ---- agravantes
        if dmarc_state != "absent":
            sp, p = dmarc.get("subdomain_policy"), dmarc.get("policy")
            if sp and p and STRENGTH[sp] < STRENGTH[p]:
                level = _level_max(level, "LIMITED")
                factors.append(
                    f"La política de subdominios (sp={sp}) es más débil que la del dominio (p={p}); "
                    "afecta a subdominios, no al dominio exacto."
                )
                fixes.append("Alinear sp con p o eliminar sp para que los subdominios hereden la política.")

        min_bits = (dkim or {}).get("min_rsa_bits")
        if min_bits is not None and min_bits < WEAK_DKIM_BITS:
            level = _level_max(level, "MODERATE")
            factors.append(
                f"Existe una clave DKIM RSA de {min_bits} bits; claves de ese tamaño se consideran débiles y "
                "podrían permitir forjar firmas alineadas (no se verificó ni se intentó)."
            )
            fixes.append("Rotar las claves DKIM débiles a RSA de 2048 bits.")

        non_sending = _non_sending(ctx, spf)
        if non_sending and dmarc_state != "enforced":
            fixes.append(
                "El dominio parece no enviar correo (SPF '-all' sin remitentes y sin MX): publicar "
                "'v=DMARC1; p=reject;' para reducir su uso como remitente."
            )

        evidence = self._evidence(spf, dmarc, dkim, spf_state, dmarc_state, non_sending)
        ctx.data["spoofing"] = {
            "level": level,
            "factors": list(factors),
            "spf_state": spf_state,
            "dmarc_state": dmarc_state,
        }

        if level == "MINIMAL":
            return [self._f(
                "SPOOF-100", "Controles de autenticación coherentes con protección contra suplantación",
                description="La configuración DNS visible es consistente con la aplicación de DMARC sobre el dominio exacto.",
                evidence=[*evidence, *[f"Factor: {f}" for f in factors]],
                severity=Severity.INFORMATIONAL, category=FindingCategory.INFORMATIONAL,
                technical=(
                    "Con DMARC en aplicación al 100% y SPF sin +all, un tercero tendría que pasar SPF o DKIM "
                    "alineados con el dominio para que su mensaje no sea tratado por la política."
                ),
                impact="Menor exposición a suplantación del dominio exacto; esto no garantiza el resultado en cada receptor.",
                remediation="Mantener los reportes DMARC y revisar la configuración al añadir nuevos proveedores de correo.",
                confidence=Confidence.MEDIUM,
            )]

        return [self._f(
            "SPOOF-001",
            f"Riesgo {LEVEL_TEXT[level]} de suplantación del dominio exacto (evaluación por DNS)",
            description=(
                "La combinación de SPF, DKIM y DMARC visible en DNS deja margen para que mensajes que usan este "
                "dominio en el From no sean bloqueados. Es una estimación, no una comprobación."
            ),
            evidence=[*evidence, *[f"Factor: {f}" for f in factors]],
            severity=LEVEL_SEVERITY[level], category=FindingCategory.POTENTIAL_RISK,
            technical=(
                "DMARC bloquea el From falsificado solo si el mensaje falla SPF y DKIM alineados y la política es "
                "quarantine o reject. SPF y DKIM por separado no protegen el From visible. Aquí se evalúa cuántas "
                "de esas condiciones se cumplen según la configuración publicada."
            ),
            impact=(
                "Es posible que correos que aparenten venir del dominio lleguen a clientes o socios, con riesgo "
                "reputacional y de fraude. No se ha demostrado que ocurra: depende de cada receptor."
            ),
            remediation=" ".join(dict.fromkeys(fixes)) or "Revisar la configuración de SPF, DKIM y DMARC.",
            confidence=Confidence.MEDIUM,
        )]

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _evidence(
        spf: dict[str, Any], dmarc: dict[str, Any], dkim: dict[str, Any] | None,
        spf_state: str, dmarc_state: str, non_sending: bool,
    ) -> list[str]:
        spf_text = {
            "permissive": "+all (permite a cualquiera)", "strict": "-all (estricto)",
            "soft": "~all (softfail)", "neutral": "neutral o sin 'all'",
            "absent": "ausente, duplicado o inválido",
        }[spf_state]
        dmarc_text = {
            "absent": "ausente o inválido", "monitor": "monitoreo (none, o pct=0)",
            "partial": f"aplicación parcial (pct={dmarc.get('pct')})",
            "enforced": f"aplicación completa (p={dmarc.get('effective_policy')}, pct=100)",
        }[dmarc_state]
        if dkim is None:
            dkim_text = "no evaluado"
        elif dkim.get("valid"):
            dkim_text = f"{len(dkim['valid'])} selector(es) válido(s) entre los consultados"
        else:
            dkim_text = "sin selectores válidos entre los consultados (no concluyente)"
        lines = [f"SPF: {spf_text}", f"DMARC: {dmarc_text}", f"DKIM: {dkim_text}"]
        if non_sending:
            lines.append("El dominio parece no enviar correo (SPF '-all' sin remitentes y sin MX).")
        return lines

    def _indeterminate(self, spf: dict | None, dmarc: dict | None) -> Finding:
        missing = []
        if spf is None or spf.get("present") is None:
            missing.append("SPF")
        if dmarc is None or dmarc.get("present") is None:
            missing.append("DMARC")
        return self._f(
            "SPOOF-002", "Riesgo de suplantación no evaluable con los datos disponibles",
            description="No se pudo determinar la configuración de " + " y ".join(missing) + ".",
            evidence=["Datos faltantes o incompletos: " + ", ".join(missing)],
            severity=Severity.INFORMATIONAL, category=FindingCategory.REQUIRES_VALIDATION,
            technical="Sin SPF y DMARC conocidos, no se puede estimar el riesgo; no se concluye nada a favor ni en contra.",
            impact="Ninguno directo; la evaluación de suplantación es incompleta.",
            remediation="Repetir el escaneo. Si persiste, revisar los servidores DNS del dominio.",
            confidence=Confidence.LOW,
        )

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
    ) -> Finding:
        return Finding(
            id=fid, module=self.name, title=title, description=description,
            evidence=evidence, severity=severity, category=category,
            technical_explanation=technical, business_impact=impact,
            remediation=remediation, confidence=confidence,
            validation_limitations=SPOOF_LIMITS,
        )