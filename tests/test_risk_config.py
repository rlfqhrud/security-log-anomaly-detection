"""risk_config.py: 설정 로드/classify/참고 라벨 테스트."""

import risk_config
from risk_config import HIGH_RISK, LOW_RISK, MEDIUM_RISK, classify


def test_classify_uses_current_config_thresholds():
    assert classify(0.1) == LOW_RISK
    assert classify(0.29) == LOW_RISK
    assert classify(0.3) == MEDIUM_RISK
    assert classify(0.49) == MEDIUM_RISK
    assert classify(0.5) == HIGH_RISK
    assert classify(1.0) == HIGH_RISK


def test_classify_accepts_override_thresholds_without_mutating_global():
    # compare_risk_thresholds.py가 쓰는 패턴: 전역 설정을 바꾸지 않고
    # 다른 임계값으로 미리 계산해볼 수 있어야 한다.
    assert classify(0.25, medium_threshold=0.2, high_threshold=0.5) == MEDIUM_RISK
    assert classify(0.25) == LOW_RISK  # 전역 기본값은 그대로


def test_level_meta_returns_reference_and_meaning():
    meta = risk_config.level_meta(HIGH_RISK)
    assert meta["label"] == HIGH_RISK
    assert "cvss" in meta["reference"]
    assert "kisa_alert" in meta["reference"]
    assert meta["meaning"]


def test_level_meta_unknown_label_returns_none():
    assert risk_config.level_meta("존재하지않는등급") is None


def test_all_level_meta_has_three_levels_keyed_by_label():
    meta = risk_config.all_level_meta()
    assert set(meta.keys()) == {LOW_RISK, MEDIUM_RISK, HIGH_RISK}


def test_default_config_used_when_file_missing(tmp_path):
    missing_path = tmp_path / "does_not_exist.yaml"
    config = risk_config.load_config(missing_path)
    assert config["levels"]["low"]["max_score"] == 0.3
    assert config["levels"]["medium"]["max_score"] == 0.5
