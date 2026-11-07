"""Utilidades puras para registros DKIM (RFC 6376, RFC 8301, RFC 8463).

Sin red ni dependencias externas: recibe texto y devuelve estructuras. Incluye un
lector DER mínimo para obtener el tamaño de la clave RSA publicada en `p=`.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_WS_RE = re.compile(r"\s+")
_TAG_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_LOOKS_LIKE_DKIM_RE = re.compile(r"(^|;)\s*(v\s*=\s*DKIM1|p\s*=)", re.IGNORECASE)

# OID rsaEncryption (1.2.840.113549.1.1.1) codificado en DER.
_OID_RSA = bytes.fromhex("2a864886f70d010101")


@dataclass
class DkimTags:
    tags: dict[str, str]
    errors: list[str] = field(default_factory=list)


@dataclass
class KeyInfo:
    key_type: str                 # "rsa", "ed25519" o "unsupported"
    bits: int | None = None       # tamaño del módulo RSA, si se pudo leer
    revoked: bool = False         # p= vacío: clave revocada
    error: str | None = None      # problema que impide usar la clave

    @property
    def valid(self) -> bool:
        return self.error is None and not self.revoked


def looks_like_dkim(record: str) -> bool:
    """True si el TXT parece un registro de clave DKIM (v=DKIM1 o con p=)."""
    return bool(_LOOKS_LIKE_DKIM_RE.search(record))


def parse_tags(record: str) -> DkimTags:
    """Separa un registro `tag=valor; tag=valor` (nombres en minúsculas)."""
    tags: dict[str, str] = {}
    errors: list[str] = []
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            errors.append(f"Fragmento sin '=': '{part[:40]}'.")
            continue
        name, _, value = part.partition("=")
        name = name.strip().lower()
        if not _TAG_NAME_RE.match(name):
            errors.append(f"Nombre de etiqueta inválido: '{name[:20]}'.")
            continue
        if name in tags:
            errors.append(f"La etiqueta '{name}' aparece más de una vez.")
            continue
        tags[name] = value.strip()
    return DkimTags(tags=tags, errors=errors)


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Lee un elemento DER; devuelve (tag, inicio_valor, fin_valor)."""
    if pos + 2 > len(data):
        raise ValueError("estructura DER truncada")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("longitud DER inválida")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise ValueError("estructura DER truncada")
    return tag, pos, end


def rsa_bits_from_spki(der: bytes) -> int:
    """Tamaño en bits del módulo de una clave RSA en formato SubjectPublicKeyInfo."""
    tag, start, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("no es una estructura SubjectPublicKeyInfo")

    tag, alg_start, alg_end = _read_tlv(der, start)          # AlgorithmIdentifier
    if tag != 0x30:
        raise ValueError("falta el identificador de algoritmo")
    tag, oid_start, oid_end = _read_tlv(der, alg_start)
    if tag != 0x06:
        raise ValueError("falta el OID del algoritmo")
    if der[oid_start:oid_end] != _OID_RSA:
        raise ValueError("el algoritmo de la clave no es RSA")

    tag, bs_start, bs_end = _read_tlv(der, alg_end)          # BIT STRING
    if tag != 0x03 or bs_end - bs_start < 2 or der[bs_start] != 0:
        raise ValueError("campo de clave pública inválido")
    inner = der[bs_start + 1:bs_end]

    tag, seq_start, _ = _read_tlv(inner, 0)                   # RSAPublicKey
    if tag != 0x30:
        raise ValueError("estructura RSAPublicKey inválida")
    tag, n_start, n_end = _read_tlv(inner, seq_start)         # módulo
    if tag != 0x02:
        raise ValueError("módulo RSA inválido")
    modulus = inner[n_start:n_end].lstrip(b"\x00")
    if not modulus:
        raise ValueError("módulo RSA vacío")
    tag, _, _ = _read_tlv(inner, n_end)                       # exponente
    if tag != 0x02:
        raise ValueError("exponente RSA inválido")
    return (len(modulus) - 1) * 8 + modulus[0].bit_length()


def analyze_key(tags: dict[str, str]) -> KeyInfo:
    """Valida v=, k= y p= y, si es posible, obtiene el tipo y tamaño de la clave."""
    key_type = tags.get("k", "rsa").strip().lower()
    version = tags.get("v")
    if version is not None and version != "DKIM1":
        return KeyInfo(key_type=key_type, error=f"Versión no soportada (v={version}); se esperaba DKIM1.")

    if "p" not in tags:
        return KeyInfo(key_type=key_type, error="Falta la etiqueta p= con la clave pública.")
    raw_key = _WS_RE.sub("", tags["p"])
    if raw_key == "":
        return KeyInfo(key_type=key_type, revoked=True)

    try:
        der = base64.b64decode(raw_key + "=" * (-len(raw_key) % 4), validate=True)
    except (binascii.Error, ValueError):
        return KeyInfo(key_type=key_type, error="El valor de p= no es base64 válido.")

    if key_type == "rsa":
        try:
            return KeyInfo(key_type="rsa", bits=rsa_bits_from_spki(der))
        except ValueError as exc:
            return KeyInfo(key_type="rsa", error=f"Clave RSA ilegible: {exc}.")
    if key_type == "ed25519":
        if len(der) != 32:
            return KeyInfo(
                key_type="ed25519",
                error=f"Una clave Ed25519 mide 32 bytes; esta mide {len(der)}.",
            )
        return KeyInfo(key_type="ed25519", bits=256)
    return KeyInfo(
        key_type="unsupported",
        error=f"Tipo de clave k={key_type} no soportado por este análisis.",
    )