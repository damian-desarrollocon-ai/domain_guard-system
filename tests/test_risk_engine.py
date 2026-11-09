import random

import pytest

from domainguard.config import RiskConfig
from domainguard.core.risk_engine import assess, describe_method, rating_for
from domainguard.models.findings import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
)

C, P, I, V = (
    FindingCategory.CONFIRMED,
    FindingCategory.POTENTIAL_RISK,
    FindingCategory.INFORMATIONAL,
    FindingCategory.REQUIRES_VALIDATION,
)
CRIT, HIGH, MED, LOW, INFO = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL,
)
H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW


def mk(fid, sev, cat=C, conf=H, module="mod_a"):
    return Finding(
        id=fid, module=module, title=f"Hallazgo {fid}", description="d", evidence=[],
        severity=sev, category=cat, technical_explanation="t", business_impact="b",
        remediation="r", confidence=conf, validation_limitations="l",
    )


def test_no_findings_is_perfect():
    r = assess([])
    assert (r.score, r.grade, r.rating, r.total_deduction) == (100, "A", "Excelente", 0)
    assert r.partial is False and r.ceiling_applied is None
    assert any("No se detectaron" in n for n in r.notes)


def test_informational_findings_never_deduct():
    r = assess([mk("A-1", INFO, I), mk("A-2", INFO, C), mk("A-3", HIGH, V)])
    assert r.score == 100 and r.total_deduction == 0
    assert r.ceiling_applied is None  # un HIGH que no descuenta no activa techo


def test_confirmed_medium_deduction():
    r = assess([mk("A-1", MED)])
    assert r.total_deduction == 12 and r.score == 88 and r.grade == "B"


def test_confidence_and_category_factors():
    r = assess([mk("A-1", HIGH, P, M)])
    assert r.lines[0].raw_deduction == pytest.approx(22 * 0.8 * 0.7, abs=0.01)


def test_derived_finding_is_weighted_and_explained():
    r = assess([mk("SPOOF-001", HIGH, P, M, module="spoofing_analysis")])
    assert r.lines[0].derived_factor == 0.5
    assert r.lines[0].applied_deduction == pytest.approx(22 * 0.8 * 0.7 * 0.5, abs=0.01)
    assert any("SPOOF-001" in n and "50%" in n for n in r.notes)


def test_module_cap_limits_deduction_proportionally():
    findings = [mk(f"A-{i}", MED) for i in range(5)]          # 60 puntos en un módulo
    r = assess(findings)
    assert r.total_deduction == 45 and r.score == 55
    assert r.module_deductions == {"mod_a": 45.0}
    assert sum(l.applied_deduction for l in r.lines) == pytest.approx(45, abs=0.05)
    assert any("tope" in n for n in r.notes)


def test_cap_is_per_module_not_global():
    findings = [mk(f"A-{i}", MED, module="a") for i in range(5)] + [mk("B-1", MED, module="b")]
    r = assess(findings)
    assert r.total_deduction == 57  # 45 + 12


def test_critical_ceiling():
    r = assess([mk("A-1", CRIT)])
    assert r.score_before_ceiling == 60 and r.score == 49 and r.ceiling_applied == "CRITICAL"
    assert r.grade == "D"
    assert any("techo" in n for n in r.notes)


def test_high_ceiling():
    r = assess([mk("A-1", HIGH)])
    assert (r.score_before_ceiling, r.score, r.ceiling_applied) == (78, 69, "HIGH")


def test_medium_ceiling_blocks_excellent():
    r = assess([mk("A-1", MED, P, L)])        # 12 x 0.5 x 0.7 = 4.2
    assert r.score_before_ceiling == 96 and r.score == 89 and r.ceiling_applied == "MEDIUM"
    assert r.grade == "B"


def test_low_findings_have_no_ceiling():
    r = assess([mk("A-1", LOW)])
    assert r.score == 96 and r.ceiling_applied is None and r.grade == "A"


def test_score_never_below_zero():
    findings = [mk(f"{m}-1", CRIT, module=m) for m in "abcde"]
    r = assess(findings)
    assert r.score == 0 and r.grade == "F"


def test_incomplete_findings_mark_score_as_provisional():
    r = assess([mk("DKIM-008", INFO, I), mk("A-1", MED)])
    assert r.partial is True
    assert r.partial_reasons == ["DKIM-008: Hallazgo DKIM-008"]
    assert any("provisional" in n for n in r.notes)


def test_complete_analysis_is_not_partial():
    assert assess([mk("A-1", MED)]).partial is False


def test_counts():
    r = assess([mk("A-1", MED), mk("A-2", MED), mk("A-3", INFO, I)])
    assert r.counts_by_severity["MEDIUM"] == 2 and r.counts_by_severity["INFORMATIONAL"] == 1
    assert r.counts_by_severity["CRITICAL"] == 0
    assert r.counts_by_category["confirmed"] == 2 and r.counts_by_category["informational"] == 1


def test_score_is_independent_of_finding_order():
    findings = [mk("A-1", MED), mk("B-1", HIGH, P, M, module="b"), mk("C-1", LOW, module="c"),
                mk("SPOOF-001", HIGH, P, M, module="spoofing_analysis")]
    expected = assess(findings)
    for seed in range(5):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        r = assess(shuffled)
        assert (r.score, r.total_deduction) == (expected.score, expected.total_deduction)


@pytest.mark.parametrize(
    "score, grade",
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")],
)
def test_rating_bands(score, grade):
    assert rating_for(score)[0] == grade


def test_custom_config_changes_result():
    cfg = RiskConfig(
        severity_points={CRIT: 10.0, HIGH: 5.0, MED: 2.0, LOW: 1.0, INFO: 0.0},
        score_ceilings={},
    )
    r = assess([mk("A-1", MED)], cfg)
    assert r.total_deduction == 2 and r.score == 98 and r.ceiling_applied is None


def test_method_text_reflects_config_values():
    text = " ".join(describe_method())
    assert "45" in text and "100" in text and "ni demuestra" in text
    custom = " ".join(describe_method(RiskConfig(module_deduction_cap=30.0)))
    assert "30" in custom


def test_lines_expose_full_breakdown():
    r = assess([mk("A-1", HIGH, P, M)])
    line = r.lines[0]
    assert (line.base_points, line.confidence_factor, line.category_factor) == (22.0, 0.8, 0.7)
    assert line.finding_id == "A-1" and line.module == "mod_a"