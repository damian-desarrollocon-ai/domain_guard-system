import base64

import pytest

from domainguard.core.dkim_parse import (
    analyze_key,
    looks_like_dkim,
    parse_tags,
    rsa_bits_from_spki,
)

# Claves reales generadas con la librería cryptography (validan el formato DER real).
REAL_RSA_1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjCSEOjA0VZGeT/58HnGWk8YUektLEwwzJrMBvwcG0eOqB6bIm2GI4f4yPvBSSO/a2B0tnDKtn3+C0tfCbS6ZFosLzhf0mCaptFhy1HCHAQlraqU+irdxTlBp+2EW3l2iLXh80sIUTFFRt7XG1afjKTrHRxm6/9rqE70oZ7cPRewIDAQAB"
REAL_RSA_2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+A6KqVdejvmNE3C8Bg7SXTepPrDpggcTq8MuMNKbjFyHn0gwBnF9ZedoG3lzBbtTGtOSt87lCKjBARYHuG2aGictDRQ9O4mldP/5yN0BPba5HO/WEo5q5rNIIFIPAenP0pcFPzbM0wCyZybBQtFFSxDolt7oT23/YTjP7mI8DTU3h5xye/EazXq4E1rgZP2sWnA8YWVI9eyUAaxPCNXUiKoJxUIctyCGe5ytW77D0/imk8d/zeQXr0S4t6lYezMR6t7QrTlfsyNZa19ANfHv92wmvqMUjFV56AanpDKnpaSjL4sINYn/uWQ2HJW2HgMLqCKF15n9lClBJkEL85EYcwIDAQAB"
REAL_ED25519 = "6Y751ycmUajEg5WJICBOs9a8801IMo+cm79oiN2iOJU="


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def synthetic_spki(bits):
    """Construye una SubjectPublicKeyInfo RSA con un módulo del tamaño pedido."""
    n = (1 << (bits - 1)) | 1
    n_bytes = n.to_bytes((bits + 7) // 8, "big")
    if n_bytes[0] & 0x80:
        n_bytes = b"\x00" + n_bytes
    rsa_key = _der(0x30, _der(0x02, n_bytes) + _der(0x02, b"\x01\x00\x01"))
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    return _der(0x30, alg + _der(0x03, b"\x00" + rsa_key))


def b64(raw):
    return base64.b64encode(raw).decode()


# -------------------------------------------------------------- tags
def test_parse_tags_basic():
    t = parse_tags("v=DKIM1; k=rsa; p=ABC ; t=y:s;")
    assert t.errors == []
    assert t.tags == {"v": "DKIM1", "k": "rsa", "p": "ABC", "t": "y:s"}


def test_parse_tags_errors():
    t = parse_tags("v=DKIM1; k=rsa; k=ed25519; garbage; 9x=1")
    assert len(t.errors) == 3


@pytest.mark.parametrize(
    "rec, expected",
    [
        ("v=DKIM1; k=rsa; p=ABC", True),
        ("p=ABC", True),
        ("V=DKIM1;p=", True),
        ("v=spf1 -all", False),
        ("google-site-verification=xyz", False),
    ],
)
def test_looks_like_dkim(rec, expected):
    assert looks_like_dkim(rec) is expected


# -------------------------------------------------------------- DER / RSA
def test_real_keys_are_measured_correctly():
    assert rsa_bits_from_spki(base64.b64decode(REAL_RSA_1024)) == 1024
    assert rsa_bits_from_spki(base64.b64decode(REAL_RSA_2048)) == 2048


@pytest.mark.parametrize("bits", [512, 768, 1024, 1536, 2048, 3072, 4096])
def test_synthetic_keys_match_requested_size(bits):
    assert rsa_bits_from_spki(synthetic_spki(bits)) == bits


def test_synthetic_matches_real_format():
    # El constructor de pruebas y el parser coinciden con una clave real
    assert rsa_bits_from_spki(synthetic_spki(2048)) == rsa_bits_from_spki(base64.b64decode(REAL_RSA_2048))


@pytest.mark.parametrize(
    "der",
    [b"", b"\x30", b"\x30\x03\x01\x02", b"\x04\x02\x00\x00", b"\x30\x82\xff\xff" + b"\x00" * 10],
)
def test_malformed_der_raises_value_error(der):
    with pytest.raises(ValueError):
        rsa_bits_from_spki(der)


def test_ed25519_oid_is_not_rsa():
    ed_spki = _der(0x30, _der(0x30, _der(0x06, bytes.fromhex("2b6570"))) + _der(0x03, b"\x00" + b"\x01" * 32))
    with pytest.raises(ValueError):
        rsa_bits_from_spki(ed_spki)


# -------------------------------------------------------------- analyze_key
def test_analyze_rsa_ok():
    info = analyze_key(parse_tags(f"v=DKIM1; k=rsa; p={REAL_RSA_2048}").tags)
    assert info.valid and info.bits == 2048 and info.key_type == "rsa"


def test_k_defaults_to_rsa():
    info = analyze_key(parse_tags(f"p={REAL_RSA_1024}").tags)
    assert info.valid and info.bits == 1024


def test_p_with_whitespace_is_accepted():
    spaced = " ".join(REAL_RSA_2048[i:i + 60] for i in range(0, len(REAL_RSA_2048), 60))
    info = analyze_key(parse_tags(f"v=DKIM1; p={spaced}").tags)
    assert info.valid and info.bits == 2048


def test_revoked_key():
    info = analyze_key(parse_tags("v=DKIM1; k=rsa; p=").tags)
    assert info.revoked and not info.valid and info.error is None


def test_missing_p():
    info = analyze_key(parse_tags("v=DKIM1; k=rsa").tags)
    assert info.error and "p=" in info.error


def test_bad_base64():
    info = analyze_key(parse_tags("v=DKIM1; p=%%%notbase64%%%").tags)
    assert info.error and "base64" in info.error


def test_garbage_key_bytes():
    info = analyze_key(parse_tags(f"v=DKIM1; p={b64(b'hola mundo')}").tags)
    assert info.error and "ilegible" in info.error


def test_wrong_version():
    info = analyze_key(parse_tags(f"v=DKIM2; p={REAL_RSA_2048}").tags)
    assert info.error and "DKIM1" in info.error


def test_ed25519_ok_and_wrong_length():
    assert analyze_key(parse_tags(f"v=DKIM1; k=ed25519; p={REAL_ED25519}").tags).valid
    bad = analyze_key(parse_tags(f"v=DKIM1; k=ed25519; p={b64(b'x' * 10)}").tags)
    assert bad.error and "32" in bad.error


def test_unsupported_key_type():
    info = analyze_key(parse_tags(f"v=DKIM1; k=dsa; p={REAL_RSA_2048}").tags)
    assert info.key_type == "unsupported" and info.error