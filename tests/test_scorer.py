from src.sbom_tm.scorer import compute_score


def test_compute_score_high_value():
    vuln = {"cvss": 8.0, "exploit_maturity": "PROOF_OF_CONCEPT"}
    context = {"value_metric": "high", "exposure": {"internet": 1.0}}
    factors = {
        "cvss_weight": 0.5,
        "exploitability_weight": 0.3,
        "asset_value_weight": 0.15,
        "exposure_weight": 0.05,
    }
    score = compute_score(vuln, context, factors, pattern_multiplier=1.2)
    assert score > 80


def test_compute_score_defaults():
    vuln = {"cvss": 5.0}
    context = {}
    factors = {}
    score = compute_score(vuln, context, factors)
    assert 0 <= score <= 100
def test_compute_score_handles_missing_values():
    vuln = {}
    context = {"value_metric": "medium"}
    factors = {}
    score = compute_score(vuln, context, factors)
    assert isinstance(score, float)
    assert score == 9 
