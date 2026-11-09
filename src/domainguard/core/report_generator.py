"""Generación de reportes. Por ahora: JSON (el HTML llega en el siguiente paso)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from domainguard.models.scan_result import ScanResult


def to_json(result: ScanResult) -> str:
    """Serializa el resultado completo; conserva los acentos (UTF-8)."""
    return json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2)


def default_report_path(result: ScanResult, extension: str, base_dir: str | Path = "reports_output") -> Path:
    stamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", result.domain.lower())
    return Path(base_dir) / f"{safe_domain}_{stamp}.{extension.lstrip('.')}"


def write_json(result: ScanResult, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_json(result) + "\n", encoding="utf-8")
    return target