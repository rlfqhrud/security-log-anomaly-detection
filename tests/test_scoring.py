"""scoring.py: RiskScorer 점수 누적/등급 분류/score_breakdown 테스트."""

from scoring import HIGH_RISK, LOW_RISK, MEDIUM_RISK, RiskScorer


def _hit(entity, attack_type, score, detail, source_ip="203.0.113.1"):
    return {
        "entity": entity,
        "attack_type": attack_type,
        "score": score,
        "detail": detail,
        "source_ip": source_ip,
    }


def test_single_low_score_hit_classified_low_risk():
    scorer = RiskScorer()
    scorer.add_hits([_hit("S1", "브루트포스 공격", 0.25, "60초 이내 로그인 실패 5회")])

    results = scorer.results()
    assert len(results) == 1
    assert results[0]["level"] == LOW_RISK
    assert results[0]["score"] == 0.25


def test_combined_hits_can_cross_into_high_risk():
    scorer = RiskScorer()
    scorer.add_hits([
        _hit("S1", "브루트포스 공격", 0.25, "60초 이내 로그인 실패 5회"),
        _hit("S1", "웹 공격(SQL 인젝션)", 0.6, "SQL 인젝션 의심 요청: /search?q=..."),
    ])

    results = scorer.results()
    assert results[0]["level"] == HIGH_RISK
    assert results[0]["score"] == 0.85  # 0.25 + 0.6 = 0.85 (1.0 미만이라 clip 없음)


def test_score_clips_at_one(monkeypatch=None):
    scorer = RiskScorer()
    scorer.add_hits([
        _hit("S1", "웹 공격(SQL 인젝션)", 0.6, "a"),
        _hit("S1", "웹 공격(SQL 인젝션)", 0.6, "b"),
    ])
    results = scorer.results()
    assert results[0]["score"] == 1.0


def test_score_breakdown_reports_per_rule_contribution():
    scorer = RiskScorer()
    scorer.add_hits([
        _hit("S1", "브루트포스 공격", 0.25, "60초 이내 로그인 실패 5회"),
        _hit("S1", "웹 공격(SQL 인젝션)", 0.6, "SQL 인젝션 의심 요청"),
    ])

    breakdown = scorer.results()[0]["score_breakdown"]
    assert len(breakdown) == 2
    assert {b["attack_type"] for b in breakdown} == {"브루트포스 공격", "웹 공격(SQL 인젝션)"}
    assert sum(b["score"] for b in breakdown) == 0.85


def test_incidents_only_returns_high_risk_entities():
    scorer = RiskScorer()
    scorer.add_hits([
        _hit("LOW1", "브루트포스 공격", 0.25, "d1"),
        _hit("HIGH1", "웹 공격(SQL 인젝션)", 0.6, "d2"),
    ])

    incidents = scorer.incidents()
    assert len(incidents) == 1
    assert incidents[0]["entity"] == "HIGH1"


def test_source_ips_aggregated_per_entity():
    scorer = RiskScorer()
    scorer.add_hits([
        _hit("S1", "브루트포스 공격", 0.25, "d1", source_ip="1.2.3.4"),
        _hit("S1", "DoS 공격", 0.55, "d2", source_ip="1.2.3.4"),
    ])
    assert scorer.results()[0]["source_ips"] == ["1.2.3.4"]


def test_no_hits_means_no_results():
    scorer = RiskScorer()
    assert scorer.results() == []
    assert scorer.incidents() == []
