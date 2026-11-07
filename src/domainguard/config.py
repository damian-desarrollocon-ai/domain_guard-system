"""Configuración central de DomainGuard.

Los valores por defecto son conservadores y pasivos. Se ampliará con los pesos
del motor de riesgo y las opciones de red en pasos posteriores.
"""
from __future__ import annotations

# Selectores DKIM comunes que se consultan por defecto (configurables por el usuario).
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "selector1",
    "selector2",
    "google",
    "default",
    "mail",
    "s1",
    "s2",
    "k1",
    "dkim",
    "smtp",
)