"""Utilidades puras para registros DMARC (RFC 7489). Sin red ni dependencias externas."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from domainguard.core.dkim_parse import parse_tags  # mismo formato tag=valor

POLICIES = ("none", "quarantine", "reject")
STRENGTH = {"none": 0, "quarantine": 1, "reject": 2}

_DMARC_START_RE = re.compile(r"^\s*v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"^[^@\s,;!]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
_PCT_RE = re.compile(r"^\d{1,3}$")


@dataclass
class DmarcRecord:
    raw: str
    tags: dict[str, str]
    policy: str | None = None             # p= efectivo (None si el registro es inutilizable)
    subdomain_policy: str | None = None   # sp=
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    rua: list[str] = field(default_factory=list)   # direcciones de reportes agregados
    ruf: list[str] = field(default_factory=list)   # direcciones de reportes forenses
    treated_as_none: bool = False         # p= ausente/inválido con rua válido
    fatal: list[str] = field(default_factory=list)      # el receptor ignora el registro
    warnings: list[str] = field(default_factory=list)   # problemas que no lo invalidan


def is_dmarc_record(text: str) -> bool:
    """True si el TXT comienza con v=DMARC1 (única forma válida de identificarlo)."""
    return bool(_DMARC_START_RE.match(text))


def _parse_uris(value: str, tag: str, warnings: list[str]) -> list[str]:
    addresses: list[str] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if item.lower().startswith("mailto:"):
            address = item[7:].split("!")[0]
            if _EMAIL_RE.match(address):
                addresses.append(address.lower())
            else:
                warnings.append(f"{tag}: dirección inválida '{item[:60]}'.")
        else:
            warnings.append(f"{tag}: URI sin 'mailto:' o de esquema poco soportado ('{item[:60]}').")
    return addresses


def parse_dmarc(record: str) -> DmarcRecord:
    parsed = parse_tags(record)
    tags = parsed.tags
    result = DmarcRecord(raw=record, tags=tags, warnings=list(parsed.errors))

    if not tags or next(iter(tags)) != "v" or tags["v"].upper() != "DMARC1":
        result.fatal.append("La etiqueta v=DMARC1 debe ser la primera del registro.")

    if "rua" in tags:
        result.rua = _parse_uris(tags["rua"], "rua", result.warnings)
    if "ruf" in tags:
        result.ruf = _parse_uris(tags["ruf"], "ruf", result.warnings)

    p = tags.get("p")
    if p is not None and p.lower() in POLICIES:
        result.policy = p.lower()
    else:
        problem = "Falta la etiqueta p=." if p is None else f"Valor de p= inválido: '{p[:20]}'."
        if result.rua:
            result.policy = "none"
            result.treated_as_none = True
            result.warnings.append(
                problem + " Con una URI rua válida, los receptores lo tratan como p=none."
            )
        else:
            result.fatal.append(
                problem + " Sin una URI rua válida, los receptores ignoran el registro."
            )

    if "sp" in tags:
        if tags["sp"].lower() in POLICIES:
            result.subdomain_policy = tags["sp"].lower()
        else:
            result.warnings.append(f"Valor de sp= inválido: '{tags['sp'][:20]}'.")

    if "pct" in tags:
        if _PCT_RE.match(tags["pct"]) and int(tags["pct"]) <= 100:
            result.pct = int(tags["pct"])
        else:
            result.warnings.append(f"Valor de pct= inválido ('{tags['pct'][:10]}'); se asume 100.")

    for tag in ("adkim", "aspf"):
        if tag in tags:
            if tags[tag].lower() in ("r", "s"):
                setattr(result, tag, tags[tag].lower())
            else:
                result.warnings.append(f"Valor de {tag}= inválido ('{tags[tag][:10]}'); se asume 'r'.")

    return result