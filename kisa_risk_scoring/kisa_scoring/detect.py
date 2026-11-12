"""이상탐지 단계: LightGBM으로 CICIDS2017 flow를 정상 또는 공격 유형으로 판정한다.

판정 결과는 원본 CSV에 'pred' 컬럼으로 붙여 저장하고, 위험도 산정 단계
(python -m kisa_scoring --pred ...)가 그대로 읽는다.

왜 교차 예측(out-of-fold)인가
    CICIDS2017은 요일마다 공격 유형이 다르다(화: Patator, 수: DoS, 목: 웹·침투, 금: 봇·포트스캔·DDoS).
    화·수로만 학습하면 목·금의 유형을 아예 모르므로, 전체 flow를 k개로 나눠
    "자기 자신을 학습에 쓰지 않은 모델"의 판정을 각 flow에 붙인다.
    이렇게 만든 판정은 위험도 단계의 보정(화·수)/평가(목·금) 분리와 독립적이다.
    한계: flow를 무작위로 나누므로 같은 공격 세션의 flow가 학습·판정 양쪽에 들어갈 수 있어
    탐지 성능이 실제 운영보다 높게 나올 수 있다. 논문에 이 점을 적는다.

실행:
    python -m kisa_scoring.detect --input Monday.csv Tuesday.csv ... --out-dir pred_csv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .adapters.base import BENIGN
from .adapters.cicids2017 import normalize_label

# 학습에서 빼는 컬럼(소문자·공백 제거 기준). 식별자·시각·포트 번호를 쓰면 실험망에 과적합된다.
EXCLUDE = {
    "flow id", "source ip", "src ip", "destination ip", "dst ip", "source port", "src port",
    "timestamp", "label", "pred", "raw_ref",
}
LABEL_KEYS = ("label",)


def _key(col) -> str:
    return str(col).strip().lower()


def find_label_column(df: pd.DataFrame) -> str:
    for col in df.columns:
        if _key(col) in LABEL_KEYS:
            return col
    raise ValueError("정답 레이블 컬럼(Label)이 없습니다. 학습에는 레이블이 필요합니다.")


def feature_columns(df: pd.DataFrame) -> list[str]:
    """학습에 쓸 숫자형 특징 컬럼."""
    cols = []
    for col in df.columns:
        if _key(col) in EXCLUDE:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            cols.append(col)
    if not cols:
        raise ValueError("학습에 쓸 숫자형 특징 컬럼이 없습니다.")
    return cols


def to_matrix(df: pd.DataFrame, cols: list[str]) -> np.ndarray:
    """inf → NaN, float32 행렬. LightGBM은 NaN을 결측으로 처리한다."""
    x = df[cols].to_numpy(dtype=np.float64, na_value=np.nan)
    x[~np.isfinite(x)] = np.nan
    return x.astype(np.float32)


def make_model(seed: int = 42, n_estimators: int = 300, class_weight: str | None = "balanced"):
    from lightgbm import LGBMClassifier

    return LGBMClassifier(
        n_estimators=n_estimators,
        learning_rate=0.1,
        num_leaves=63,
        importance_type="gain",      # 분할 횟수가 아니라 정보 이득 기준 (잡음 특징이 부풀지 않게)
        class_weight=class_weight,   # Heartbleed·Infiltration처럼 드문 유형이 묻히지 않게
        random_state=seed,
        n_jobs=-1,
        verbose=-1,
    )


def out_of_fold_predict(x: np.ndarray, y: np.ndarray, folds: int = 5, seed: int = 42,
                        model_factory=make_model) -> tuple[np.ndarray, np.ndarray]:
    """StratifiedKFold 교차 예측. (판정, 특징 중요도 평균)을 돌려준다.

    표본이 folds보다 적은 유형은 층화가 안 되므로 해당 fold 수를 줄인다.
    """
    from sklearn.model_selection import StratifiedKFold

    counts = pd.Series(y).value_counts()
    k = int(max(2, min(folds, counts.min()))) if counts.min() >= 2 else 2
    if k < folds:
        print(f"[경고] 가장 드문 유형의 표본이 {counts.min()}건이라 fold 수를 {k}로 줄입니다.", file=sys.stderr)
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=seed)
    pred = np.empty(len(y), dtype=object)
    importances = np.zeros(x.shape[1])
    for i, (tr, te) in enumerate(skf.split(x, y), 1):
        model = model_factory(seed=seed)
        model.fit(x[tr], y[tr])
        pred[te] = model.predict(x[te])
        importances += getattr(model, "feature_importances_", np.zeros(x.shape[1]))
        print(f"  fold {i}/{k} 완료", file=sys.stderr)
    return pred, importances / k


def detection_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """논문 '[탐지 성능 수치]'에 넣을 지표: 정확도, macro-F1, 이진(정상/이상) 지표, 유형별 리포트."""
    from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

    yt_bin = y_true != BENIGN
    yp_bin = y_pred != BENIGN
    return {
        "flows": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "binary_precision": float(precision_score(yt_bin, yp_bin, zero_division=0)),
        "binary_recall": float(recall_score(yt_bin, yp_bin, zero_division=0)),
        "binary_f1": float(f1_score(yt_bin, yp_bin, zero_division=0)),
        "false_positive_rate": float((yp_bin & ~yt_bin).sum() / max(1, (~yt_bin).sum())),
        "per_class": classification_report(y_true, y_pred, output_dict=True, zero_division=0),
    }


def run(inputs: list[str], out_dir: str, folds: int = 5, seed: int = 42, binary: bool = False,
        pred_col: str = "pred") -> dict:
    """CSV들을 읽어 교차 예측하고, 각 CSV를 pred 컬럼을 붙여 out_dir에 같은 이름으로 저장한다."""
    frames = []
    for path in inputs:
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df["__file"] = Path(path).name
        frames.append(df)
    raw = pd.concat(frames, ignore_index=True)

    label_col = find_label_column(raw)
    y = normalize_label(raw[label_col]).to_numpy(dtype=object)
    if binary:
        y = np.where(y == BENIGN, BENIGN, "Anomaly").astype(object)
    cols = feature_columns(raw.drop(columns=["__file"]))
    if pred_col in cols:
        cols.remove(pred_col)
    x = to_matrix(raw, cols)

    print(f"[이상탐지] LightGBM, flow {len(raw):,}건, 특징 {len(cols)}개, 유형 {len(set(y))}개, {folds}-fold 교차 예측",
          file=sys.stderr)
    pred, imp = out_of_fold_predict(x, y, folds=folds, seed=seed)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    raw[pred_col] = pred
    for name, part in raw.groupby("__file", sort=False):
        part.drop(columns=["__file"]).to_csv(out / name, index=False, encoding="latin-1", errors="replace")

    metrics = detection_metrics(y, pred)
    metrics["model"] = "LightGBM (LGBMClassifier, class_weight=balanced)"
    metrics["mode"] = "binary" if binary else "multiclass"
    metrics["folds"] = folds
    with open(out / "detect_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    (pd.DataFrame({"feature": [str(c).strip() for c in cols], "importance": imp})
       .sort_values("importance", ascending=False)
       .to_csv(out / "feature_importance.csv", index=False, encoding="utf-8-sig"))
    return metrics


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    p = argparse.ArgumentParser(prog="python -m kisa_scoring.detect",
                                description="LightGBM 이상탐지: CICIDS2017 CSV에 판정 컬럼(pred)을 붙인다")
    p.add_argument("--input", nargs="+", required=True, help="GeneratedLabelledFlows CSV (여러 요일)")
    p.add_argument("--out-dir", required=True, help="pred 컬럼을 붙인 CSV와 지표를 저장할 폴더")
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--binary", action="store_true", help="정상/이상 이진 분류 (위험도 binary 모드용)")
    args = p.parse_args(argv)

    m = run(args.input, args.out_dir, folds=args.folds, seed=args.seed, binary=args.binary)
    print(f"[탐지 성능] 정확도 {m['accuracy']:.4f}  macro-F1 {m['macro_f1']:.4f}  "
          f"이진 정밀도 {m['binary_precision']:.4f}  재현율 {m['binary_recall']:.4f}  오탐률 {m['false_positive_rate']:.4%}")
    print(f"출력 폴더: {Path(args.out_dir).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
