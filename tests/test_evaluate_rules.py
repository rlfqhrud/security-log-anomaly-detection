"""evaluate_rules.py 테스트: harness 로직 자체의 정확성 확인.

작은 통제된 입력으로 TP/FN/FP 계산, 분위수 후보, 스윕 로직이 맞는지
검증한다. 여기서 나오는 숫자는 "우리 룰의 성능"이 아니라 harness
코드가 올바른지를 보는 것 - 입력도 기대값도 전부 이 테스트 파일 안에서
직접 통제한다.
"""

import pandas as pd

from evaluate_rules import (
    class_recall,
    compute_confusion,
    print_sweep_table,
    quantile_candidates,
    threshold_sweep,
)


def _fake_rule_matches(row_indices):
    """row_indices에 해당하는 행만 "탐지됐다"고 보고하는 가짜 룰 함수를 만든다."""
    def rule_fn(df, config=None):
        return [{"row_index": idx} for idx in row_indices if idx in df.index]
    return rule_fn


def _toy_df():
    return pd.DataFrame({
        "Label": ["BENIGN", "BENIGN", "AttackX", "AttackX", "AttackY"],
    })


def test_perfect_match_gives_precision_recall_one():
    df = _toy_df()
    rule_fn = _fake_rule_matches([2, 3])  # AttackX 두 행 정확히 맞춤
    result = compute_confusion(df, rule_fn, positive_labels={"AttackX"})

    assert result["tp"] == 2
    assert result["fn"] == 0
    assert result["fp"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0


def test_false_positive_on_benign_is_counted_and_labeled():
    df = _toy_df()
    rule_fn = _fake_rule_matches([0, 2, 3])  # BENIGN 행(0)을 잘못 잡음
    result = compute_confusion(df, rule_fn, positive_labels={"AttackX"})

    assert result["tp"] == 2
    assert result["fp"] == 1
    assert result["fp_by_label"] == {"BENIGN": 1}


def test_false_positive_on_other_attack_label_is_counted():
    df = _toy_df()
    rule_fn = _fake_rule_matches([2, 3, 4])  # AttackY(다른 공격)까지 잡음
    result = compute_confusion(df, rule_fn, positive_labels={"AttackX"})

    assert result["fp"] == 1
    assert result["fp_by_label"] == {"AttackY": 1}


def test_no_matches_gives_zero_precision_recall():
    df = _toy_df()
    rule_fn = _fake_rule_matches([])
    result = compute_confusion(df, rule_fn, positive_labels={"AttackX"})

    assert result["tp"] == 0
    assert result["fn"] == 2
    assert result["precision"] is None  # tp+fp == 0 이라 나눗셈 불가
    assert result["recall"] == 0.0


def test_empty_positive_labels_means_no_positives_to_recall():
    df = _toy_df()
    rule_fn = _fake_rule_matches([0])
    result = compute_confusion(df, rule_fn, positive_labels=set())

    assert result["tp"] == 0
    assert result["fp"] == 1
    assert result["recall"] is None  # tp+fn == 0


def test_class_recall_separates_rare_class_from_majority():
    df = pd.DataFrame({"Label": ["Common"] * 20 + ["Rare"]})
    # Common은 전부 잡지만 Rare는 하나도 못 잡는 룰
    rule_fn = _fake_rule_matches(list(range(20)))

    recall = class_recall(df, rule_fn, positive_labels={"Common", "Rare"})

    assert recall["Common"]["recall"] == 1.0
    assert recall["Rare"]["recall"] == 0.0  # 전체 평균(20/21=95%)에 안 묻힘
    assert recall["Rare"]["total"] == 1


def test_class_recall_handles_label_not_present():
    df = _toy_df()
    rule_fn = _fake_rule_matches([])
    recall = class_recall(df, rule_fn, positive_labels={"NeverSeen"})
    assert recall["NeverSeen"] == {"total": 0, "matched": 0, "recall": None}


def test_quantile_candidates_excludes_inf_and_nan():
    df = pd.DataFrame({"pps": [1.0, 2.0, 3.0, 4.0, float("inf"), float("nan")]})
    candidates = quantile_candidates(df, "pps", quantiles=(0.5,))
    assert candidates == [2.5]  # inf/NaN 제외한 [1,2,3,4]의 중앙값


def test_threshold_sweep_tries_each_candidate_independently():
    df = _toy_df()

    def rule_fn(df, config):
        threshold = config["min_score"]
        # threshold가 낮을수록 더 많이 잡는 가짜 룰
        matched = [2, 3] if threshold <= 1 else [2]
        return [{"row_index": i} for i in matched]

    rows = threshold_sweep(
        df, rule_fn, {"min_score": 0}, ("min_score",), [1, 5],
        positive_labels={"AttackX"},
    )
    assert rows[0]["threshold"] == 1
    assert rows[0]["recall"] == 1.0
    assert rows[1]["threshold"] == 5
    assert rows[1]["recall"] == 0.5


def test_print_sweep_table_does_not_crash_on_none_values(capsys):
    rows = [{"threshold": 1, "tp": 0, "fn": 0, "fp": 0, "precision": None, "recall": None, "f1": None}]
    print_sweep_table(rows)
    captured = capsys.readouterr()
    assert "threshold" in captured.out
