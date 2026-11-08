"""Análisis de DMARC mediante lectura pasiva de registros DNS públicos (RFC 7489)."""
from __future__ import annotations

from domainguard.core.dmarc_parse import (
    STRENGTH,
    DmarcRecord,
    is_dmarc_record,
    parse_dmarc,
)
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

from .base import BaseModule, ScanContext

FAILED_STATUSES = {"timeout", "servfail", "error"}
MAX_PARENT_LOOKUPS = 3
MAX_EXTERNAL_CHECKS = 5

POLICY_EXPLANATIONS = {
    "none": "p=none (monitoreo): el receptor no toma acción sobre mensajes que fallan DMARC; solo se generan reportes si hay rua.",
    "quarantine": "p=quarantine (cuarentena): los mensajes que fallan DMARC deben tratarse como sospechosos, por ejemplo enviarse a spam.",
    "reject": "p=reject (rechazo): los mensajes que fallan DMARC deben rechazarse durante la transacción SMTP.",
}

DMARC_LIMITS = (
    "Análisis de DNS únicamente: no prueba que un mensaje falsificado real sea aceptado o rechazado. "
    "Cada receptor decide con su propia política y filtros, y DMARC solo se evalúa cuando el dominio "
    "aparece en el encabezado From. La herencia desde el dominio principal se aproxima sin la Lista "
    "de Sufijos Públicos."
)


def _parent_domains(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, min(len(labels) - 1, MAX_PARENT_LOOKUPS + 1))]


def _is_internal(address_domain: str, record_domain: str) -> bool:
    return address_domain == record_domain or address_domain.endswith("." + record_domain)


class DmarcAnalysisModule(BaseModule):
    name = "dmarc_analysis"

    # ------------------------------------------------------------------ run
    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.data.get("domain_exists") is False:
            return []

        queried: list[str] = []
        found_at: str | None = None
        records: list[str] = []
        for candidate in [ctx.domain, *_parent_domains(ctx.domain)]:
            qname = f"_dmarc.{candidate}"
            queried.append(qname)
            answer = ctx.resolver.query(qname, "TXT")
            if answer.status in FAILED_STATUSES:
                ctx.data["dmarc"] = {"present": None}
                return [self._incomplete([f"{qname}: {answer.status}"], partial=False)]
            matching = [r for r in answer.records if is_dmarc_record(r)]
            if matching:
                found_at, records = candidate, matching
                break

        if found_at is None:
            ctx.data["dmarc"] = {"present": False, "valid": False, "effective_policy": None}
            return [self._missing(ctx.domain, queried)]

        inherited = found_at != ctx.domain
        if len(records) > 1:
            ctx.data["dmarc"] = {
                "present": True, "valid": False, "effective_policy": None,
                "record_domain": found_at, "inherited": inherited,
            }
            return [self._multiple(records)]

        rec = parse_dmarc(records[0])
        effective = None if rec.fatal else (
            (rec.subdomain_policy or rec.policy) if inherited else rec.policy
        )
        ctx.data["dmarc"] = {
            "present": True,
            "valid": not rec.fatal,
            "record": rec.raw,
            "record_domain": found_at,
            "inherited": inherited,
            "policy": rec.policy,
            "subdomain_policy": rec.subdomain_policy,
            "effective_policy": effective,
            "pct": rec.pct,
            "adkim": rec.adkim,
            "aspf": rec.aspf,
            "has_rua": bool(rec.rua),
            "has_ruf": bool(rec.ruf),
            "external_unauthorized": [],
        }

        findings: list[Finding] = []
        problems = [*rec.fatal, *rec.warnings]
        if problems:
            findings.append(self._f(
                "DMARC-003", "Problemas de sintaxis en el registro DMARC",
                description=(
                    "El registro DMARC es inutilizable para los receptores." if rec.fatal
                    else "El registro DMARC contiene valores que los receptores pueden ignorar o corregir."
                ),
                evidence=[rec.raw, *[f"  - {p}" for p in problems]],
                severity=Severity.MEDIUM if rec.fatal else Severity.LOW,
                category=FindingCategory.CONFIRMED,
                technical=(
                    "Según RFC 7489, un registro sin v=DMARC1 al inicio, o sin p= válido y sin rua válido, "
                    "se descarta, y el dominio queda sin política DMARC efectiva."
                    if rec.fatal else
                    "Las etiquetas inválidas se ignoran o se reemplazan por sus valores por defecto, "
                    "lo que puede producir un comportamiento distinto al pretendido."
                ),
                impact="La política que el dueño cree tener podría no aplicarse.",
                remediation="Corregir los valores indicados según RFC 7489 y verificar con un validador de DMARC.",
                confidence=Confidence.HIGH,
            ))
            if rec.fatal:
                return findings

        policy = effective or "none"

        if policy == "none":
            has_reports = bool(rec.rua)
            findings.append(self._f(
                "DMARC-004", "Política DMARC en modo monitoreo (p=none)",
                description="La política efectiva no pide a los receptores acción alguna sobre mensajes que fallan DMARC.",
                evidence=[
                    rec.raw,
                    f"Política efectiva: {policy}" + (" (heredada de sp= del dominio principal)" if inherited and rec.subdomain_policy else ""),
                    "Reportes agregados (rua): " + (", ".join(rec.rua) if has_reports else "no configurados"),
                ],
                severity=Severity.LOW if has_reports else Severity.MEDIUM,
                category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    POLICY_EXPLANATIONS["none"] + " Es una fase normal de despliegue, pero por sí sola "
                    "no instruye a bloquear suplantaciones del dominio. "
                    + ("Con rua activo hay visibilidad para avanzar." if has_reports
                       else "Sin rua tampoco hay visibilidad sobre quién envía como este dominio.")
                ),
                impact=(
                    "Mensajes que usen este dominio en el From y fallen la autenticación no serían "
                    "bloqueados por política DMARC; su destino real depende de cada receptor."
                ),
                remediation=(
                    "Mantener rua, revisar los reportes, corregir remitentes legítimos y avanzar de forma "
                    "gradual a p=quarantine y luego p=reject." if has_reports
                    else "Agregar rua=mailto:..., revisar los reportes y avanzar gradualmente a quarantine y reject."
                ),
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))
        elif policy == "quarantine":
            findings.append(self._f(
                "DMARC-005", "Política DMARC en cuarentena (p=quarantine)",
                description="Los mensajes que fallan DMARC deben tratarse como sospechosos.",
                evidence=[rec.raw],
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical=POLICY_EXPLANATIONS["quarantine"] + " Es una política con aplicación real; p=reject es el paso siguiente.",
                impact="Protección parcial: los mensajes sospechosos pueden seguir llegando a la carpeta de spam.",
                remediation="Valorar p=reject cuando los reportes confirmen que los remitentes legítimos pasan DMARC.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        if policy in ("quarantine", "reject") and rec.pct < 100:
            findings.append(self._f(
                "DMARC-006", f"Política DMARC aplicada solo al {rec.pct}% de los mensajes (pct)",
                description="La política se aplica a una fracción de los mensajes que fallan DMARC.",
                evidence=[rec.raw, f"pct={rec.pct}"],
                severity=Severity.MEDIUM if rec.pct == 0 else Severity.LOW,
                category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    "Con pct menor a 100, solo ese porcentaje de los mensajes que fallan recibe la política; "
                    "el resto recibe la inmediatamente más débil. pct=0 equivale en la práctica a monitoreo."
                ),
                impact="La protección contra suplantación es parcial mientras pct no llegue a 100.",
                remediation="Completar el despliegue y subir pct a 100 (o eliminar la etiqueta) tras validar los reportes.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        if rec.subdomain_policy and STRENGTH[rec.subdomain_policy] < STRENGTH[rec.policy or "none"]:
            weak_sp = rec.subdomain_policy
            findings.append(self._f(
                "DMARC-007", "Política de subdominios (sp) más débil que la del dominio",
                description=f"p={rec.policy} pero sp={weak_sp}: los subdominios tienen una política menos estricta.",
                evidence=[rec.raw],
                severity=Severity.MEDIUM if weak_sp == "none" else Severity.LOW,
                category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    "sp rige los subdominios que no publican su propio registro DMARC. Una política más débil "
                    "ahí permite que remitentes no autenticados usen subdominios sin que se aplique la política del dominio."
                ),
                impact="Los subdominios podrían usarse como remitente con menos fricción que el dominio principal.",
                remediation="Alinear sp con p (o eliminar sp para que los subdominios hereden p) cuando sea viable.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        if not rec.rua and policy in ("quarantine", "reject"):
            findings.append(self._f(
                "DMARC-008", "Sin reportes agregados DMARC (rua)",
                description="El registro no define dónde enviar reportes agregados.",
                evidence=[rec.raw],
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical="Sin rua el dueño no recibe datos sobre remitentes que pasan o fallan DMARC.",
                impact="Menos visibilidad para detectar remitentes legítimos mal configurados o abusos.",
                remediation="Agregar rua=mailto:buzon@dominio y revisar los reportes periódicamente.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        if rec.ruf:
            findings.append(self._f(
                "DMARC-010", "Reportes forenses DMARC configurados (ruf)",
                description="El registro solicita reportes de fallos individuales.",
                evidence=[f"ruf: {', '.join(rec.ruf)}"],
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical=(
                    "Muchos receptores no envían reportes forenses por privacidad. Si llegan, pueden contener "
                    "datos de los mensajes, por lo que el buzón debe protegerse."
                ),
                impact="Posible tratamiento de datos personales en el buzón receptor.",
                remediation="Confirmar que el buzón ruf está protegido y que su uso cumple la normativa de privacidad aplicable.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        incomplete: list[str] = []
        unauthorized = self._check_external(ctx, found_at, rec, incomplete)
        ctx.data["dmarc"]["external_unauthorized"] = unauthorized
        if unauthorized:
            findings.append(self._f(
                "DMARC-012", "Destino externo de reportes sin autorización publicada",
                description="Algún destino de reportes en otro dominio no publica la autorización esperada.",
                evidence=unauthorized,
                severity=Severity.LOW,
                category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    "Para enviar reportes a un dominio distinto, RFC 7489 §7.1 espera un TXT v=DMARC1 en "
                    "<dominio>._report._dmarc.<destino>. Sin él, muchos receptores no enviarán los reportes."
                ),
                impact="Los reportes DMARC podrían no llegar, dejando al dueño sin visibilidad.",
                remediation="Pedir al operador del destino que publique el registro de autorización o usar un buzón del propio dominio.",
                confidence=Confidence.MEDIUM,
                limitations=DMARC_LIMITS + " Algunos receptores no aplican esta verificación.",
            ))
        if incomplete:
            findings.append(self._incomplete(incomplete, partial=True))

        if rec.adkim == "s" or rec.aspf == "s":
            findings.append(self._f(
                "DMARC-014", "Alineación estricta en DMARC",
                description="Se usa alineación estricta (adkim=s y/o aspf=s).",
                evidence=[f"adkim={rec.adkim}", f"aspf={rec.aspf}"],
                severity=Severity.INFORMATIONAL,
                category=FindingCategory.INFORMATIONAL,
                technical=(
                    "Con alineación estricta el dominio del From debe coincidir exactamente con el dominio "
                    "autenticado por DKIM/SPF; la relajada (por defecto) admite subdominios del mismo dominio principal."
                ),
                impact="Más protección, pero los correos enviados desde subdominios pueden fallar DMARC si no se configuran.",
                remediation="Confirmar con los reportes que los remitentes legítimos mantienen alineación estricta antes de endurecer la política.",
                confidence=Confidence.HIGH,
                limitations=DMARC_LIMITS,
            ))

        evidence = [
            rec.raw,
            f"Registro encontrado en: _dmarc.{found_at}" + (" (heredado del dominio principal)" if inherited else ""),
            f"Política efectiva: {policy}" + (" (p= ausente o inválido con rua válido)" if rec.treated_as_none else ""),
            f"pct={rec.pct}; adkim={rec.adkim}; aspf={rec.aspf}",
            f"rua: {len(rec.rua)} destino(s); ruf: {len(rec.ruf)} destino(s)",
        ]
        findings.append(self._f(
            "DMARC-100", "Resumen del registro DMARC",
            description="Registro DMARC único detectado y analizado.",
            evidence=evidence,
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.INFORMATIONAL,
            technical=" ".join(POLICY_EXPLANATIONS.values()),
            impact="Ninguno por sí mismo.",
            remediation="Ninguna requerida.",
            confidence=Confidence.HIGH,
            limitations=DMARC_LIMITS,
        ))
        return findings

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _check_external(
        ctx: ScanContext, record_domain: str, rec: DmarcRecord, incomplete: list[str]
    ) -> list[str]:
        domains: list[str] = []
        for address in [*rec.rua, *rec.ruf]:
            domain = address.rsplit("@", 1)[1]
            if not _is_internal(domain, record_domain) and domain not in domains:
                domains.append(domain)

        unauthorized: list[str] = []
        for domain in domains[:MAX_EXTERNAL_CHECKS]:
            qname = f"{record_domain}._report._dmarc.{domain}"
            answer = ctx.resolver.query(qname, "TXT")
            if answer.status in FAILED_STATUSES:
                incomplete.append(f"{qname}: {answer.status}")
            elif not any(is_dmarc_record(r) for r in answer.records):
                unauthorized.append(f"{domain}: sin registro de autorización en {qname}")
        if len(domains) > MAX_EXTERNAL_CHECKS:
            incomplete.append(
                f"Solo se verificaron {MAX_EXTERNAL_CHECKS} de {len(domains)} dominios externos de reportes."
            )
        return unauthorized

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
        limitations: str = DMARC_LIMITS,
    ) -> Finding:
        return Finding(
            id=fid, module=self.name, title=title, description=description,
            evidence=evidence, severity=severity, category=category,
            technical_explanation=technical, business_impact=impact,
            remediation=remediation, confidence=confidence,
            validation_limitations=limitations,
        )

    def _missing(self, domain: str, queried: list[str]) -> Finding:
        return self._f(
            "DMARC-001", "No se encontró registro DMARC",
            description=f"Ni '{domain}' ni su dominio principal publican un registro DMARC.",
            evidence=["Nombres consultados: " + ", ".join(queried)],
            severity=Severity.MEDIUM,
            category=FindingCategory.CONFIRMED,
            technical=(
                "Sin DMARC, el dueño del dominio no indica a los receptores qué hacer con mensajes que "
                "fallan SPF/DKIM ni recibe reportes de uso del dominio."
            ),
            impact=(
                "Aumenta la exposición a la suplantación del dominio en el From. No prueba que un correo "
                "falsificado concreto sea aceptado: depende de SPF, DKIM y de cada receptor."
            ),
            remediation=(
                "Publicar en _dmarc.<dominio> un TXT inicial como 'v=DMARC1; p=none; rua=mailto:buzon@dominio', "
                "revisar los reportes y avanzar a quarantine y reject. Si el dominio no envía correo, "
                "publicar 'v=DMARC1; p=reject'."
            ),
            confidence=Confidence.HIGH,
        )

    def _multiple(self, records: list[str]) -> Finding:
        return self._f(
            "DMARC-002", "Múltiples registros DMARC publicados",
            description=f"Se encontraron {len(records)} registros DMARC en el mismo nombre.",
            evidence=records,
            severity=Severity.MEDIUM,
            category=FindingCategory.CONFIRMED,
            technical="RFC 7489 indica que, con más de un registro DMARC, el receptor no aplica ninguno.",
            impact="El dominio queda en la práctica sin política DMARC, aunque parezca configurada.",
            remediation="Dejar un único registro DMARC en _dmarc.<dominio> y eliminar el resto.",
            confidence=Confidence.HIGH,
        )

    def _incomplete(self, evidence: list[str], *, partial: bool) -> Finding:
        return self._f(
            "DMARC-013", "Análisis DMARC incompleto",
            description="Algunas consultas no obtuvieron respuesta definitiva.",
            evidence=evidence,
            severity=Severity.INFORMATIONAL,
            category=FindingCategory.INFORMATIONAL,
            technical=(
                "Timeouts o errores de servidor impiden afirmar el contenido de ciertos registros. "
                + ("Los resultados mostrados son parciales." if partial
                   else "No se concluye si existe o no un registro DMARC.")
            ),
            impact="Ninguno directo; la evaluación de DMARC es parcial.",
            remediation="Repetir el escaneo. Si persiste, revisar los servidores DNS del dominio.",
            confidence=Confidence.MEDIUM,
        )