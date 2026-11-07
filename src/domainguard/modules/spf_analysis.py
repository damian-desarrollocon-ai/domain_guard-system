"""Análisis de SPF (RFC 7208) usando solo lectura de DNS público.

No envía correo ni evalúa IPs de remitentes. Es un análisis estático: cuenta
consultas en el peor caso y detecta problemas de sintaxis y de política.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from domainguard.core.resolver import DnsAnswer
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

from .base import BaseModule, ScanContext

FAILED_STATUSES = {"timeout", "servfail", "error"}
LOOKUP_LIMIT = 10        # RFC 7208 sección 4.6.4
NEAR_LIMIT = 8
MAX_DEPTH = 10           # niveles máximos de include/redirect
HARD_LOOKUP_CAP = 30     # tope de seguridad: no se expande más allá de esto
BROAD_V4 = 16            # prefijos menores a /16 en IPv4 se consideran muy amplios
BROAD_V6 = 32

SPF_LIMITS = (
    "Análisis estático de DNS: no demuestra qué aceptará un receptor real, "
    "que además aplica DKIM, DMARC y sus propias políticas. El conteo de "
    "consultas es de peor caso (un receptor puede detenerse antes al hallar coincidencia)."
)

_SPF_RE = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_MODIFIER_RE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)=(?P<value>.*)$")
_MECH_RE = re.compile(
    r"^(?P<q>[+\-~?])?(?P<name>all|include|exists|ip4|ip6|ptr|mx|a)(?P<rest>.*)$",
    re.IGNORECASE,
)
_CIDR_RE = re.compile(
    r"^(?::(?P<domain>[^/]+))?(?:/(?P<c4>\d{1,2}))?(?://(?P<c6>\d{1,3}))?$"
)

_POLICY_TEXT = {
    "+": "+all (permite a cualquiera)",
    "-": "-all (rechazo estricto)",
    "~": "~all (softfail)",
    "?": "?all (neutral)",
    None: "no determinada",
}


@dataclass
class SpfTerm:
    raw: str
    name: str
    qualifier: str = "+"
    value: str | None = None
    is_modifier: bool = False
    prefix_len: int | None = None


@dataclass
class ParsedSpf:
    record: str
    terms: list[SpfTerm]
    errors: list[str]


def _parse_term(raw: str, errors: list[str]) -> SpfTerm | None:
    m = _MODIFIER_RE.match(raw)
    if m:
        name = m.group("name").lower()
        value = m.group("value")
        if name in ("redirect", "exp") and not value:
            errors.append(f"Modificador '{raw}' sin valor.")
            return None
        return SpfTerm(raw=raw, name=name, value=value, is_modifier=True)

    m = _MECH_RE.match(raw)
    if not m:
        errors.append(f"Término no reconocido: '{raw}'.")
        return None

    qualifier = m.group("q") or "+"
    name = m.group("name").lower()
    rest = m.group("rest")
    term = SpfTerm(raw=raw, name=name, qualifier=qualifier)

    if name == "all":
        if rest:
            errors.append(f"'all' no admite parámetros: '{raw}'.")
            return None
        return term

    if name in ("include", "exists"):
        if not rest.startswith(":") or len(rest) < 2:
            errors.append(f"'{name}' requiere un dominio (':dominio'): '{raw}'.")
            return None
        term.value = rest[1:]
        return term

    if name == "ptr":
        if rest and not (rest.startswith(":") and len(rest) > 1):
            errors.append(f"Sintaxis inválida en '{raw}'.")
            return None
        term.value = rest[1:] or None
        return term

    if name in ("a", "mx"):
        cm = _CIDR_RE.match(rest)
        if not cm:
            errors.append(f"Sintaxis inválida en '{raw}'.")
            return None
        c4, c6 = cm.group("c4"), cm.group("c6")
        if (c4 and int(c4) > 32) or (c6 and int(c6) > 128):
            errors.append(f"Longitud de prefijo fuera de rango en '{raw}'.")
            return None
        term.value = cm.group("domain")
        return term

    # ip4 / ip6
    if not rest.startswith(":") or len(rest) < 2:
        errors.append(f"'{name}' requiere una dirección: '{raw}'.")
        return None
    try:
        net = ipaddress.ip_network(rest[1:], strict=False)
    except ValueError:
        errors.append(f"Dirección o red inválida en '{raw}'.")
        return None
    if (name == "ip4" and net.version != 4) or (name == "ip6" and net.version != 6):
        errors.append(f"La dirección no corresponde al tipo '{name}': '{raw}'.")
        return None
    term.value = rest[1:]
    term.prefix_len = net.prefixlen
    return term


def parse_spf(record: str) -> ParsedSpf:
    terms: list[SpfTerm] = []
    errors: list[str] = []
    for raw in record.split()[1:]:
        term = _parse_term(raw, errors)
        if term is not None:
            terms.append(term)
    for mod in ("redirect", "exp"):
        if sum(1 for t in terms if t.name == mod) > 1:
            errors.append(f"El modificador '{mod}' aparece más de una vez.")
    return ParsedSpf(record=record, terms=terms, errors=errors)


@dataclass
class _Expansion:
    lookups: int = 0
    loops: list[str] = field(default_factory=list)
    broken_targets: list[str] = field(default_factory=list)
    nested_errors: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    ptr_in: list[str] = field(default_factory=list)
    broad_ranges: list[tuple[str, int]] = field(default_factory=list)
    truncated: bool = False


class SpfAnalysisModule(BaseModule):
    name = "spf_analysis"

    # ------------------------------------------------------------------ run
    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.data.get("domain_exists") is False:
            return []

        answer = ctx.resolver.query(ctx.domain, "TXT")
        if answer.status == "nxdomain":
            return []
        if answer.status in FAILED_STATUSES:
            ctx.data["spf"] = {"present": None}
            return [self._incomplete([f"TXT {ctx.domain}: {answer.status}"])]

        records = [r for r in answer.records if _SPF_RE.match(r)]
        state: dict = {
            "present": bool(records),
            "multiple": len(records) > 1,
            "record": records[0] if len(records) == 1 else None,
            "all_qualifier": None,
            "lookup_count": 0,
            "lookup_limit_exceeded": False,
            "permerror": False,
        }
        ctx.data["spf"] = state

        if not records:
            return [self._no_spf(ctx.domain)]
        if len(records) > 1:
            state["permerror"] = True
            return [self._multiple(records)]

        record = records[0]
        parsed = parse_spf(record)
        exp = _Expansion()
        self._walk(ctx, ctx.domain, parsed, [ctx.domain], 0, exp)

        qualifier = self._effective_all(ctx, parsed)
        has_all = any(t.name == "all" for t in parsed.terms)
        has_redirect = any(t.name == "redirect" for t in parsed.terms)
        count_txt = f"{'≥' if exp.truncated else ''}{exp.lookups}"
        syntax = [*parsed.errors, *exp.nested_errors]

        state.update(
            all_qualifier=qualifier,
            lookup_count=exp.lookups,
            lookup_limit_exceeded=exp.lookups > LOOKUP_LIMIT,
            permerror=bool(syntax or exp.loops or exp.broken_targets),
        )

        findings: list[Finding] = []

        if syntax:
            findings.append(self._f(
                "SPF-003", "Errores de sintaxis en el registro SPF",
                description="El registro SPF contiene términos que no cumplen el estándar.",
                evidence=[record, *syntax],
                severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
                technical=(
                    "Según RFC 7208, un término inválido provoca 'permerror': el receptor "
                    "no puede evaluar SPF y el resultado deja de aportar protección."
                ),
                impact="Los correos legítimos pueden fallar SPF y la protección contra suplantación basada en SPF se pierde.",
                remediation="Corregir o eliminar los términos inválidos. Si el error está en un include de terceros, avisar al proveedor.",
                confidence=Confidence.HIGH,
            ))

        if qualifier == "+":
            findings.append(self._f(
                "SPF-004", "SPF autoriza a cualquier servidor a enviar (+all)",
                description="La política final del SPF permite el envío desde cualquier dirección IP.",
                evidence=[record],
                severity=Severity.CRITICAL, category=FindingCategory.CONFIRMED,
                technical=(
                    "'+all' (o 'all' sin calificador) hace que SPF devuelva 'pass' para cualquier IP. "
                    "Ese 'pass' puede además satisfacer DMARC por la vía de SPF, anulando su efecto."
                ),
                impact="Elimina la protección de SPF contra el uso no autorizado del dominio como remitente.",
                remediation="Reemplazar por '-all' (o '~all' durante la transición) tras inventariar los remitentes legítimos.",
                confidence=Confidence.HIGH,
                limitations=SPF_LIMITS + " Los receptores pueden aplicar filtros adicionales (reputación, contenido).",
            ))
        elif qualifier == "?":
            findings.append(self._f(
                "SPF-005", "SPF con política neutral (?all)",
                description="La política final es neutral: no indica qué hacer con remitentes no autorizados.",
                evidence=[record],
                severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
                technical="El resultado 'neutral' equivale a no tomar posición, por lo que SPF no aporta protección efectiva.",
                impact="Los mensajes de remitentes no autorizados no son marcados por SPF.",
                remediation="Migrar a '~all' y luego a '-all' cuando el inventario de remitentes esté completo.",
                confidence=Confidence.HIGH,
            ))
        elif qualifier == "~":
            findings.append(self._f(
                "SPF-006", "SPF con softfail (~all)",
                description="La política final marca como sospechosos (no rechaza) los remitentes no autorizados.",
                evidence=[record],
                severity=Severity.INFORMATIONAL, category=FindingCategory.INFORMATIONAL,
                technical=(
                    "'~all' es una práctica común y aceptable, sobre todo con DMARC en cuarentena o rechazo. "
                    "Su efecto real depende de cómo cada receptor trate el softfail."
                ),
                impact="Protección parcial; no constituye por sí sola una debilidad.",
                remediation="Valorar '-all' cuando el inventario de remitentes sea confiable. Verificar la política DMARC.",
                confidence=Confidence.HIGH,
            ))

        if not has_all and not has_redirect:
            findings.append(self._f(
                "SPF-007", "SPF sin mecanismo 'all' ni 'redirect'",
                description="El registro no define qué hacer con remitentes que no coinciden con ningún mecanismo.",
                evidence=[record],
                severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
                technical="Sin 'all' ni 'redirect', el resultado por defecto es 'neutral', equivalente a '?all'.",
                impact="Los remitentes no autorizados no son marcados por SPF.",
                remediation="Agregar '-all' (o '~all' en transición) al final del registro.",
                confidence=Confidence.HIGH,
            ))

        if exp.lookups > LOOKUP_LIMIT:
            findings.append(self._f(
                "SPF-008", "Posible exceso del límite de 10 consultas DNS en SPF",
                description=f"El conteo de peor caso es {count_txt} consultas; el límite del estándar es {LOOKUP_LIMIT}.",
                evidence=[record, f"Consultas contadas (include, a, mx, ptr, exists, redirect): {count_txt}"],
                severity=Severity.MEDIUM, category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    "RFC 7208 exige 'permerror' si la evaluación supera 10 consultas. Como el receptor puede "
                    "detenerse al encontrar coincidencia, el exceso solo ocurre en ciertas rutas de evaluación."
                ),
                impact="Algunos correos legítimos podrían fallar SPF de forma intermitente.",
                remediation="Eliminar includes innecesarios, reemplazar por rangos ip4/ip6 o usar un servicio de aplanado de SPF.",
                confidence=Confidence.MEDIUM,
            ))
        elif exp.lookups >= NEAR_LIMIT:
            findings.append(self._f(
                "SPF-009", "SPF cerca del límite de consultas DNS",
                description=f"El conteo de peor caso es {count_txt} de {LOOKUP_LIMIT} permitidas.",
                evidence=[record, f"Consultas contadas: {count_txt}"],
                severity=Severity.INFORMATIONAL, category=FindingCategory.INFORMATIONAL,
                technical="Agregar uno o dos servicios más podría superar el límite sin que se note.",
                impact="Riesgo futuro al añadir nuevos proveedores de correo.",
                remediation="Planificar la consolidación de includes antes de añadir más remitentes.",
                confidence=Confidence.MEDIUM,
            ))

        if exp.loops:
            findings.append(self._f(
                "SPF-010", "Bucle de include/redirect en SPF",
                description="Una cadena de include o redirect se referencia a sí misma.",
                evidence=exp.loops,
                severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
                technical="Los bucles hacen que la evaluación no termine y el receptor devuelve 'permerror'.",
                impact="SPF deja de ser evaluable cuando el receptor recorre esa ruta.",
                remediation="Romper la referencia circular en alguno de los registros implicados.",
                confidence=Confidence.HIGH,
            ))

        if exp.broken_targets:
            findings.append(self._f(
                "SPF-011", "Include/redirect apunta a un dominio sin SPF utilizable",
                description="Al menos un destino referenciado no publica un único registro SPF válido.",
                evidence=exp.broken_targets,
                severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
                technical="RFC 7208 trata un include/redirect sin registro SPF (o con varios) como 'permerror'.",
                impact="SPF puede fallar para ese dominio, afectando correo legítimo y la protección esperada.",
                remediation="Corregir el nombre del destino o retirar el mecanismo si el servicio ya no se usa.",
                confidence=Confidence.HIGH,
            ))

        if exp.ptr_in:
            findings.append(self._f(
                "SPF-012", "Uso del mecanismo 'ptr' en SPF",
                description="El SPF usa 'ptr', desaconsejado por el estándar.",
                evidence=[f"ptr en: {d}" for d in exp.ptr_in],
                severity=Severity.LOW, category=FindingCategory.CONFIRMED,
                technical="RFC 7208 indica que 'ptr' NO DEBERÍA usarse: es lento, poco fiable y carga a los servidores DNS.",
                impact="Posibles fallos o lentitud en la validación del correo.",
                remediation="Sustituir 'ptr' por mecanismos 'ip4', 'ip6', 'a' o 'include'.",
                confidence=Confidence.HIGH,
            ))

        if exp.unresolved or exp.truncated:
            ev = list(exp.unresolved)
            if exp.truncated:
                ev.append(
                    f"Expansión detenida por tope de seguridad ({HARD_LOOKUP_CAP} consultas o {MAX_DEPTH} niveles)."
                )
            findings.append(self._incomplete(ev, note="El conteo de consultas es un mínimo."))

        if exp.broad_ranges:
            worst = min(p for _, p in exp.broad_ranges)
            findings.append(self._f(
                "SPF-014", "Rangos IP muy amplios autorizados en SPF",
                description="Se autorizan bloques de direcciones muy grandes para enviar correo.",
                evidence=[r for r, _ in exp.broad_ranges],
                severity=Severity.HIGH if worst == 0 else Severity.MEDIUM,
                category=FindingCategory.POTENTIAL_RISK,
                technical=(
                    f"Bloques mayores a /{BROAD_V4} (IPv4) o /{BROAD_V6} (IPv6) autorizan a muchos "
                    "hosts que probablemente no son remitentes legítimos. Un /0 equivale a '+all'."
                ),
                impact="Amplía la superficie de remitentes que pasan SPF.",
                remediation="Reducir los rangos a las direcciones realmente usadas para enviar correo.",
                confidence=Confidence.MEDIUM,
                limitations=SPF_LIMITS + " Puede ser intencional si el rango pertenece a la organización.",
            ))

        ignored = self._ignored_terms(parsed)
        if ignored:
            findings.append(self._f(
                "SPF-015", "Términos de SPF que nunca se evalúan",
                description="Hay elementos que el estándar ignora, lo que sugiere una configuración inconsistente.",
                evidence=[record, *ignored],
                severity=Severity.LOW, category=FindingCategory.CONFIRMED,
                technical="Todo lo que sigue a 'all' no se evalúa, y 'redirect' se ignora si existe 'all'.",
                impact="Un remitente legítimo agregado después de 'all' seguiría fallando SPF.",
                remediation="Reordenar el registro para que 'all' sea el último mecanismo y eliminar redirect redundantes.",
                confidence=Confidence.HIGH,
            ))

        findings.append(self._f(
            "SPF-100", "Resumen del registro SPF",
            description="Registro SPF único detectado y analizado.",
            evidence=[
                record,
                f"Política final: {_POLICY_TEXT.get(qualifier, 'no determinada')}",
                f"Consultas DNS contadas: {count_txt} (límite RFC 7208: {LOOKUP_LIMIT})",
            ],
            severity=Severity.INFORMATIONAL, category=FindingCategory.INFORMATIONAL,
            technical="Resumen para el reporte; los hallazgos individuales detallan cualquier problema.",
            impact="Ninguno por sí mismo.",
            remediation="Ninguna requerida.",
            confidence=Confidence.HIGH,
        ))
        return findings

    # ------------------------------------------------------------- recursion
    @staticmethod
    def _fetch_spf(ctx: ScanContext, domain: str) -> tuple[DnsAnswer, list[str]]:
        answer = ctx.resolver.query(domain, "TXT")
        return answer, [r for r in answer.records if _SPF_RE.match(r)]

    def _walk(
        self,
        ctx: ScanContext,
        domain: str,
        parsed: ParsedSpf,
        stack: list[str],
        depth: int,
        exp: _Expansion,
    ) -> None:
        has_all = any(t.name == "all" for t in parsed.terms)
        for term in parsed.terms:
            if exp.lookups >= HARD_LOOKUP_CAP:
                exp.truncated = True
                return
            if term.name == "all":
                break  # lo que sigue nunca se evalúa
            if term.name == "redirect" and has_all:
                continue  # redirect se ignora si existe 'all'

            if term.name in ("include", "a", "mx", "ptr", "exists", "redirect"):
                exp.lookups += 1
            if term.name == "ptr":
                exp.ptr_in.append(domain)
            if term.name in ("ip4", "ip6") and term.qualifier == "+" and term.prefix_len is not None:
                limit = BROAD_V4 if term.name == "ip4" else BROAD_V6
                if term.prefix_len < limit:
                    exp.broad_ranges.append((f"{domain}: {term.raw}", term.prefix_len))
            if term.name in ("include", "redirect"):
                self._follow(ctx, term, stack, depth, exp)

    def _follow(
        self, ctx: ScanContext, term: SpfTerm, stack: list[str], depth: int, exp: _Expansion
    ) -> None:
        target = (term.value or "").lower().rstrip(".")
        if not target:
            return
        label = f"include:{target}" if term.name == "include" else f"redirect={target}"

        if "%" in target:
            exp.unresolved.append(f"{label} (usa macros; no se expande)")
            return
        if target in stack:
            exp.loops.append(" -> ".join([*stack, target]))
            return
        if depth + 1 > MAX_DEPTH:
            exp.truncated = True
            return

        answer, records = self._fetch_spf(ctx, target)
        if answer.status in FAILED_STATUSES:
            exp.unresolved.append(f"{label} (consulta DNS: {answer.status})")
            return
        if not records:
            exp.broken_targets.append(f"{label}: sin registro SPF (estado DNS: {answer.status})")
            return
        if len(records) > 1:
            exp.broken_targets.append(f"{label}: {len(records)} registros SPF publicados")
            return

        nested = parse_spf(records[0])
        exp.nested_errors.extend(f"{target}: {e}" for e in nested.errors)
        self._walk(ctx, target, nested, [*stack, target], depth + 1, exp)

    def _effective_all(self, ctx: ScanContext, parsed: ParsedSpf) -> str | None:
        seen = {ctx.domain}
        current = parsed
        for _ in range(MAX_DEPTH):
            all_term = next((t for t in current.terms if t.name == "all"), None)
            if all_term is not None:
                return all_term.qualifier
            redirect = next((t for t in current.terms if t.name == "redirect"), None)
            if redirect is None or not redirect.value or "%" in redirect.value:
                return None
            target = redirect.value.lower().rstrip(".")
            if target in seen:
                return None
            seen.add(target)
            _, records = self._fetch_spf(ctx, target)
            if len(records) != 1:
                return None
            current = parse_spf(records[0])
        return None

    @staticmethod
    def _ignored_terms(parsed: ParsedSpf) -> list[str]:
        names = [t.name for t in parsed.terms]
        if "all" not in names:
            return []
        ignored: list[str] = []
        idx = names.index("all")
        after = [t.raw for t in parsed.terms[idx + 1:] if not t.is_modifier]
        if after:
            ignored.append("Términos posteriores a 'all' (nunca se evalúan): " + " ".join(after))
        redirects = [t.raw for t in parsed.terms if t.name == "redirect"]
        if redirects:
            ignored.append("redirect ignorado porque existe 'all': " + " ".join(redirects))
        return ignored

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
        limitations: str = SPF_LIMITS,
    ) -> Finding:
        return Finding(
            id=fid, module=self.name, title=title, description=description,
            evidence=evidence, severity=severity, category=category,
            technical_explanation=technical, business_impact=impact,
            remediation=remediation, confidence=confidence,
            validation_limitations=limitations,
        )

    def _no_spf(self, domain: str) -> Finding:
        return self._f(
            "SPF-001", "No se encontró registro SPF",
            description=f"'{domain}' no publica un registro TXT que comience con 'v=spf1'.",
            evidence=[f"TXT {domain}: sin registro SPF"],
            severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
            technical=(
                "Sin SPF, los receptores no pueden verificar qué servidores están autorizados a enviar "
                "correo con este dominio en el sobre (envelope-from)."
            ),
            impact=(
                "Aumenta la exposición a uso no autorizado del dominio y puede perjudicar la entregabilidad. "
                "Esto no prueba por sí solo que un correo falsificado sea aceptado: depende de DKIM, DMARC "
                "y de la política del receptor."
            ),
            remediation=(
                "Publicar un SPF con los remitentes legítimos y '-all'. Si el dominio no envía correo, "
                "publicar 'v=spf1 -all'."
            ),
            confidence=Confidence.HIGH,
        )

    def _multiple(self, records: list[str]) -> Finding:
        return self._f(
            "SPF-002", "Múltiples registros SPF publicados",
            description=f"Se encontraron {len(records)} registros SPF en el mismo nombre.",
            evidence=records,
            severity=Severity.MEDIUM, category=FindingCategory.CONFIRMED,
            technical="RFC 7208 exige un único registro SPF. Con varios, el receptor devuelve 'permerror'.",
            impact="SPF no puede evaluarse, por lo que no aporta protección y el correo legítimo puede fallar.",
            remediation="Fusionar los registros en uno solo y eliminar el resto.",
            confidence=Confidence.HIGH,
        )

    def _incomplete(self, evidence: list[str], note: str = "") -> Finding:
        return self._f(
            "SPF-013", "Análisis SPF incompleto",
            description="No se pudo resolver o expandir completamente el SPF.",
            evidence=evidence,
            severity=Severity.INFORMATIONAL, category=FindingCategory.INFORMATIONAL,
            technical=(
                "Timeouts, macros o el tope de seguridad impiden afirmar el contenido de ciertos registros. "
                "No se concluye nada sobre esas partes. " + note
            ).strip(),
            impact="Ninguno directo; la evaluación de SPF es parcial.",
            remediation="Repetir el escaneo. Si persiste, revisar los servidores DNS de los dominios incluidos.",
            confidence=Confidence.MEDIUM,
        )