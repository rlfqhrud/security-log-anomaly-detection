"""이상탐지 모델 비교: CICIDS2017 화~금 flow에 같은 5-fold 교차 예측을 적용해 후보 모델을 비교한다.

선정 기준은 macro-F1이다. 정확도는 BENIGN 비중(약 80%)에 묻혀 모델 간 차이가 드러나지 않고,
위험도 단계의 충격도 I는 공격 유형 판정에 달려 있으므로 드문 유형까지 고르게 맞히는 모델이 필요하다.

실행:
    python experiments/compare_models.py --data ../data/cicids2017/TrafficLabelling --out experiments/results
"""
from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kisa_scoring.detect import (  # noqa: E402
    MODELS, detection_metrics, feature_columns, find_label_column, load_inputs,
    out_of_fold_predict, to_matrix,
)
from kisa_scoring.adapters.cicids2017 import normalize_label  # noqa: E402

DAYS = ["Tuesday", "Wednesday", "Thursday", "Friday"]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True)
    p.add_argument("--out", default="experiments/results")
    p.add_argument("--models", nargs="+", default=list(MODELS))
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--benign-frac", type=float, default=0.2, help="모델 선정용으로 남길 정상 flow 비율")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--cache", default="experiments/cache_benign20", help="표본 행렬 캐시 폴더")
    p.add_argument("--n-jobs", type=int, default=None, help="모델 병렬 코어 수 제한(메모리 절약)")
    args = p.parse_args()

    cache = Path(args.cache)
    if (cache / "x.npy").exists():
        # 메모리 절약: 230만 행 pandas 표 대신 표본 행렬 캐시를 읽는다.
        x = np.load(cache / "x.npy")
        y = np.load(cache / "y.npy", allow_pickle=True)
    else:
        paths = sorted(str(f) for f in Path(args.data).glob("*.csv") if f.name.split("-")[0] in DAYS)
        raw = load_inputs(paths)
        y = normalize_label(raw[find_label_column(raw)]).to_numpy(dtype=object)
        cols = feature_columns(raw.drop(columns=["__file"]))
        x = to_matrix(raw, cols)
        del raw
        gc.collect()
        if args.benign_frac < 1.0:
            # 공격 flow는 모두 두고 정상 flow만 줄인다. 드문 유형(Heartbleed 11건 등)을 표본에서 잃지 않기 위해서다.
            rng = np.random.default_rng(args.seed)
            keep = (y != "BENIGN") | (rng.random(len(y)) < args.benign_frac)
            x, y = np.ascontiguousarray(x[keep]), y[keep]
        cache.mkdir(parents=True, exist_ok=True)
        np.save(cache / "x.npy", x)
        np.save(cache / "y.npy", y.astype(object), allow_pickle=True)
        print(f"캐시 저장: {cache}", file=sys.stderr)
    print(f"flow {len(y):,}건 (정상 표본 비율 {args.benign_frac}), 특징 {x.shape[1]}개, 유형 {len(set(y))}개",
          file=sys.stderr)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    csv_path = out / "model_comparison.csv"
    rows = pd.read_csv(csv_path).to_dict("records") if csv_path.exists() else []
    rows = [r for r in rows if r["model"] not in args.models]
    for name in args.models:
        print(f"== {name}", file=sys.stderr)
        t0 = time.perf_counter()
        def factory(seed=42, _f=MODELS[name]):
            m = _f(seed=seed)
            inner = getattr(m, "model", m)
            if args.n_jobs and hasattr(inner, "n_jobs"):
                inner.set_params(n_jobs=args.n_jobs)
            return m
        pred, _ = out_of_fold_predict(x, y, folds=args.folds, model_factory=factory)
        sec = time.perf_counter() - t0
        m = detection_metrics(y, pred)
        per = m.pop("per_class")
        row = {"model": name, "seconds": round(sec, 1), **m}
        row.update({f"f1[{k}]": v["f1-score"] for k, v in per.items() if isinstance(v, dict) and k not in
                    ("macro avg", "weighted avg")})
        rows.append(row)
        with open(out / f"metrics_{name}.json", "w", encoding="utf-8") as f:
            json.dump({**row, "per_class": per}, f, ensure_ascii=False, indent=2)
        print(f"   macro-F1 {m['macro_f1']:.4f}  정확도 {m['accuracy']:.4f}  이진F1 {m['binary_f1']:.4f}  "
              f"오탐률 {m['false_positive_rate']:.4%}  {sec:.0f}s", file=sys.stderr)
        pd.DataFrame(rows).to_csv(csv_path, index=False, encoding="utf-8-sig")
        del pred
        gc.collect()

    table = pd.DataFrame(rows).sort_values("macro_f1", ascending=False)
    print(table[["model", "macro_f1", "accuracy", "binary_precision", "binary_recall", "binary_f1",
                 "false_positive_rate", "seconds"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
