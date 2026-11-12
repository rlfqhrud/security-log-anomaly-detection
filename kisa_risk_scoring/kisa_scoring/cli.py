"""명령행 실행.

python -m kisa_scoring --pred P.csv [--calib C.csv | --params params.json] ...                 (CICIDS2017, 기본)
python -m kisa_scoring --input-format suricata --pred eve_eval.json --calib eve_calib.json ...
python -m kisa_scoring --input-format generic --pred siem_export.ndjson --config my_org.yaml ...
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from pathlib import Path

import pandas as pd

from .adapters import FORMATS, load_events, load_suricata_flows
from .evaluate import evaluate, plot_results
from .scoring import PROFILE_PATHS, RiskScorer, ScoringConfig


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m kisa_scoring", description="KISA 기반 SOC 경보 위험도 산정")
    p.add_argument("--input-format", choices=FORMATS, default="cicids2017",
                   help="입력 형식 (기본 cicids2017: TrafficLabelling CSV + 판정 컬럼)")
    p.add_argument("--pred", required=True, nargs="+", help="산정 대상 입력 파일(여러 개 가능)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--calib", nargs="+", help="공격도 경계를 학습할 보정 파일(같은 입력 형식)")
    src.add_argument("--params", help="저장된 params.json")
    p.add_argument("--pred-col", default="pred", help="[cicids2017] 판정 컬럼 (기본: pred)")
    p.add_argument("--true-col", default=None, help="정답 컬럼 (있으면 평가 수행, 예: label)")
    p.add_argument("--mode", choices=["binary", "multiclass"], default=None, help="설정 파일의 mode를 덮어쓴다")
    p.add_argument("--no-fix-12h", action="store_true", help="[cicids2017] 12시간제 오후 시각 보정을 끈다")
    p.add_argument("--suricata-flows", action="store_true",
                   help="[suricata] EVE flow 이벤트 수를 경보에 맥락(context_flows)으로 붙인다. 위험도에는 반영하지 않음")
    p.add_argument("--tp-ratio", type=float, default=0.5, help="참 경보 기준 true_attack_ratio (기본 0.5)")
    p.add_argument("--config", default=None,
                   help="설정 YAML (기본: cicids2017 → config/cicids2017.yaml, 그 외 → config/default.yaml)")
    p.add_argument("--out", default="results", help="출력 폴더")
    return p


def _json_safe(obj):
    if isinstance(obj, float) and math.isnan(obj):
        return None
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def _fmt(v) -> str:
    return "-" if v is None or (isinstance(v, float) and math.isnan(v)) else (f"{v:.3f}" if isinstance(v, float) else str(v))


def _csv_ready(alerts: pd.DataFrame) -> pd.DataFrame:
    """목록 컬럼(raw_refs, signatures)을 CSV용 문자열로 바꾼다."""
    out = alerts.copy()
    for col in ("raw_refs", "signatures"):
        if col in out.columns:
            out[col] = out[col].map(lambda v: "; ".join(map(str, v)) if isinstance(v, list) else v)
    return out


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    logging.basicConfig(level=logging.WARNING, format="[경고] %(message)s", stream=sys.stderr)

    args = build_parser().parse_args(argv)
    fmt = args.input_format

    cfg = ScoringConfig.from_yaml(args.config or PROFILE_PATHS[fmt])
    if args.mode:
        cfg.mode = args.mode
        cfg.validate()
    scorer = RiskScorer(cfg)

    keep = [args.true_col] if args.true_col else []
    fix_12h = False if args.no_fix_12h else None

    def load(paths):
        return load_events(fmt, paths, cfg, pred_col=args.pred_col, fix_12h=fix_12h, keep=keep,
                           require_labels=cfg.mode == "multiclass")

    events = load(args.pred)
    if args.params:
        scorer.load_params(args.params)
    elif args.calib:
        scorer.fit(load(args.calib))
    else:
        if cfg.attack_degree["method"] == "quantile":
            print("[경고] --calib/--params가 없어 평가 데이터로 공격도 경계를 학습합니다. "
                  "논문 실험에서는 보정 데이터를 분리하라(예: 화·수 보정 / 목·금 평가).", file=sys.stderr)
        scorer.fit(events)

    alerts = scorer.score(events, true_col=args.true_col)
    if args.suricata_flows:
        if fmt != "suricata":
            print("[경고] --suricata-flows는 --input-format suricata에서만 쓴다. 무시합니다.", file=sys.stderr)
        else:
            alerts = scorer.attach_context(alerts, load_suricata_flows(args.pred, timezone=cfg.input.get("timezone", "UTC")))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    scorer.save_params(out / "params.json")
    _csv_ready(alerts).to_csv(out / "alerts.csv", index=False, encoding="utf-8-sig")
    records = RiskScorer.to_alert_records(alerts)
    if "context_flows" in alerts.columns:
        for rec, n in zip(records, alerts.loc[alerts["risk"] >= 1, "context_flows"]):
            rec["context_flows"] = int(n)
    with open(out / "alerts.json", "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    b1, b2 = scorer.thresholds_
    print(f"[입력] {fmt}  이벤트 {len(events):,}건  [모드] {cfg.mode}  [창] {cfg.window}  [시간대] {cfg.timezone}")
    print(f"[공격도 경계] n<={b1:g} → T=1, n<={b2:g} → T=2, 그 외 T=3  ({scorer.fitted_on_})")
    counts = alerts["grade"].value_counts()
    print(f"[경보] 총 {len(alerts)}건")
    for g in scorer.grade_table:
        print(f"  {g['name']}: {int(counts.get(g['name'], 0))}건  → {g['action']}")

    if args.true_col:
        n_anom = scorer.count_anomalous(events)
        result = evaluate(alerts, scorer, n_anom, tp_ratio=args.tp_ratio)
        result["by_grade"].to_csv(out / "eval_by_grade.csv", index=False, encoding="utf-8-sig")
        result["ablation"].to_csv(out / "eval_ablation.csv", index=False, encoding="utf-8-sig")
        with open(out / "eval_summary.json", "w", encoding="utf-8") as f:
            json.dump(_json_safe(result["summary"]), f, ensure_ascii=False, indent=2)
        plot_results(result, out / "fig_eval.png")

        with pd.option_context("display.width", 120, "display.float_format", "{:.3f}".format):
            print("\n[등급별 평가]")
            print(result["by_grade"].to_string(index=False))
            print("\n[정렬 기준 비교]")
            print(result["ablation"].to_string(index=False))
        print("\n[요약]")
        for k, v in result["summary"].items():
            print(f"  {k}: {_fmt(v)}")

    print(f"\n출력 폴더: {out.resolve()}")
    return 0
