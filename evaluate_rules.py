"""룰 성능 평가 harness: TP/FN/FP, precision/recall/F1, 임계값 스윕, 클래스별 recall.

DRAFT 전체 주의사항: 이 harness는 "실제 CICIDS2017 CSV가 생기면 바로 쓸 수
있게" 만든 것이다. tests/fixtures/synthetic_cicids_sample.csv로 하는 검증은
harness 코드 자체가 버그 없이 도는지 확인하는 것뿐이고, 여기서 나오는
precision/recall 숫자는 절대 "우리 룰의 실제 성능"이 아니다 - 내가 만든
라벨을 내가 채점하는 것이므로 의미가 없다. 진짜 성능은 실제 CICIDS2017
CSV로 다시 돌려야 한다.

사용 예:
    from analyze_logs import load_dataset, clean_dataset
    from flow_rules import detect_dos_flood

    df = clean_dataset(load_dataset("<실제 CICIDS2017 CSV 경로>"))
    result = evaluate_rule(df, detect_dos_flood, positive_labels={"DoS Hulk", "DoS GoldenEye"})
    print(result)
"""

from collections import Counter


def _matched_indices(hits):
    return {h["row_index"] for h in hits}


def compute_confusion(df, rule_fn, positive_labels, label_col="Label", config=None):
    """rule_fn(df, config)이 찾아낸 행과 실제 라벨을 비교해 TP/FN/FP/TN을 센다.

    positive_labels: 이 룰이 "맞다"고 판단해야 하는 진짜 공격 라벨 집합
    (예: DoS-Flood라면 {"DoS Hulk", "DoS GoldenEye"}).
    그 외 모든 라벨(BENIGN 포함, 다른 공격 포함)은 negative로 취급한다 -
    "정상 오탐"과 "타 공격 오탐"을 합쳐서 FP로 본다(요청하신 정의 그대로).
    """
    hits = rule_fn(df, config) if config is not None else rule_fn(df)
    matched = _matched_indices(hits)

    tp = fn = fp = tn = 0
    fp_by_label = Counter()
    for idx, label in df[label_col].items():
        is_positive = label in positive_labels
        is_matched = idx in matched
        if is_positive and is_matched:
            tp += 1
        elif is_positive and not is_matched:
            fn += 1
        elif not is_positive and is_matched:
            fp += 1
            fp_by_label[label] += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "fp_by_label": dict(fp_by_label),
    }


def class_recall(df, rule_fn, positive_labels, label_col="Label", config=None):
    """공격 라벨별로 recall을 따로 낸다. 소수 클래스(예: Heartbleed 1건)가
    다수 클래스에 묻혀서 안 보이는 걸 막기 위함 - 전체 평균 recall만 보면 안 된다."""
    hits = rule_fn(df, config) if config is not None else rule_fn(df)
    matched = _matched_indices(hits)

    per_label = {}
    for label in positive_labels:
        label_rows = df[df[label_col] == label]
        total = len(label_rows)
        if total == 0:
            per_label[label] = {"total": 0, "matched": 0, "recall": None}
            continue
        matched_count = sum(1 for idx in label_rows.index if idx in matched)
        per_label[label] = {
            "total": total,
            "matched": matched_count,
            "recall": matched_count / total,
        }
    return per_label


def threshold_sweep(df, rule_fn, config_template, param_path, candidate_values, positive_labels, label_col="Label"):
    """param_path가 가리키는 설정값을 candidate_values로 바꿔가며
    precision/recall/F1을 비교한다. config_template은 변경하지 않고
    매 시도마다 깊은 복사해서 쓴다.

    param_path 예: ("dos_flood", "min_flow_packets_per_sec")
    """
    import copy

    rows = []
    for value in candidate_values:
        config = copy.deepcopy(config_template)
        node = config
        for key in param_path[:-1]:
            node = node[key]
        node[param_path[-1]] = value

        result = compute_confusion(df, rule_fn, positive_labels, label_col=label_col, config=config)
        rows.append({"threshold": value, **result})
    return rows


def quantile_candidates(df, column, quantiles=(0.5, 0.75, 0.9, 0.95, 0.99)):
    """해당 컬럼의 실제 값 분포에서 분위수 후보값을 뽑는다 (스윕 후보값을
    감으로 찍지 않고 데이터 분포 기준으로 잡기 위함). inf/NaN은 제외."""
    import numpy as np

    series = df[column].replace([np.inf, -np.inf], np.nan).dropna()
    return [round(float(series.quantile(q)), 2) for q in quantiles]


def print_sweep_table(rows, label="threshold"):
    header = f"{label:>14} | {'TP':>4} | {'FN':>4} | {'FP':>4} | {'precision':>9} | {'recall':>7} | {'F1':>6}"
    print(header)
    print("-" * len(header))
    for r in rows:
        p = f"{r['precision']:.2f}" if r["precision"] is not None else "-"
        rec = f"{r['recall']:.2f}" if r["recall"] is not None else "-"
        f1 = f"{r['f1']:.2f}" if r["f1"] is not None else "-"
        print(f"{r['threshold']:>14} | {r['tp']:>4} | {r['fn']:>4} | {r['fp']:>4} | {p:>9} | {rec:>7} | {f1:>6}")
