"""Validación estricta de entradas para reducir riesgo de SSRF.

Solo se aceptan nombres de dominio públicos (FQDN). Se rechazan IPs, URLs,
puertos, credenciales y sufijos de uso interno.
"""
from __future__ import annotations

import ipaddress
import re


class DomainValidationError(ValueError):
    """La entrada no es un dominio público válido."""


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_FORBIDDEN_CHARS = set("/\\?#@:% \t\r\n[]()<>\"'")
_BLOCKED_SUFFIXES = (
    ".local", ".localhost", ".localdomain", ".internal", ".intranet",
    ".lan", ".home.arpa", ".corp", ".private", ".invalid", ".test",
)


def validate_domain(raw: str) -> str:
    """Devuelve el dominio normalizado (minúsculas, IDNA/punycode) o lanza error."""
    if not isinstance(raw, str) or not raw.strip():
        raise DomainValidationError("El dominio está vacío.")

    value = raw.strip().lower()
    if value.endswith("."):
        value = value[:-1]

    if any(ch in _FORBIDDEN_CHARS for ch in value):
        raise DomainValidationError(
            "Debe ser un nombre de dominio simple: sin esquema, ruta, puerto, "
            "credenciales ni espacios."
        )

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise DomainValidationError("No se permiten direcciones IP; use un dominio.")

    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainValidationError(f"Dominio con caracteres inválidos: {exc}") from exc

    if len(ascii_name) > 253:
        raise DomainValidationError("El dominio excede 253 caracteres.")

    labels = ascii_name.split(".")
    if len(labels) < 2:
        raise DomainValidationError("Debe incluir un TLD (p. ej. ejemplo.com).")
    if any(not _LABEL_RE.match(label) for label in labels):
        raise DomainValidationError("Una o más etiquetas del dominio no son válidas.")
    if labels[-1].isdigit():
        raise DomainValidationError("El TLD no puede ser numérico.")
    if ascii_name == "localhost" or ascii_name.endswith(_BLOCKED_SUFFIXES):
        raise DomainValidationError("Los dominios de uso interno no están permitidos.")

    return ascii_name


def is_public_ip(ip: str) -> bool:
    """True solo para direcciones IP globalmente enrutables."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast