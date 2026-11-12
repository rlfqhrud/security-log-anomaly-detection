"""LogHub 검증 결과 지표 계산: 경보 집약, 등급 분포, LLM 요약 사실 일치 검사.

LogHub에는 공격 정답 레이블이 없어 정밀도·AUC는 계산하지 않는다(CICIDS2017로 평가).
여기서는 (1) 경보 우선순위화가 얼마나 줄여 주는지와 (2) LLM 요약이 입력에 없는 사실을
만들지 않았는지를 본다.

실행 (kisa_risk_scoring 폴더에서): python examples/loghub/evaluate_loghub.py
"""
import json
import re
import statistics as st
from collections import Counter
from pathlib import Path

D = Path(__file__).resolve().parent
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TIA_RE = re.compile(r"\b([TIA])\s*=\s*(\d)")
COUNT_RE = re.compile(r"(\d+)\s*건")


def load_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def fact_check(rec):
    """요약문의 IP·T/I/A·건수가 입력 레코드와 일치하는지."""
    text = rec["summary"]
    allowed_ips = set(str(rec.get("src_ips") or "").split(";")) | {rec.get("dst_ip")}
    ips = set(IP_RE.findall(text))
    bad_ips = sorted(ips - allowed_ips)
    tia = {k: int(v) for k, v in TIA_RE.findall(text)}
    bad_tia = {k: v for k, v in tia.items() if rec.get(k) != v}
    counts = {int(c) for c in COUNT_RE.findall(text)}
    count_ok = (not counts) or rec["flow_count"] in counts
    return {
        "risk": rec["risk"], "dst_ip": rec["dst_ip"], "window_start": rec["window_start"],
        "unknown_ips": bad_ips, "wrong_tia": bad_tia, "count_matches": count_ok,
        "mentions_rationale": all(f"{k}={rec[k]}" in text.replace(" ", "") for k in ("T", "I", "A")),
        "ok": not bad_ips and not bad_tia and count_ok,
    }


def main():
    conv = json.loads((D / "events" / "convert_summary.json").read_text(encoding="utf-8"))
    alerts = json.loads((D / "results" / "alerts.json").read_text(encoding="utf-8"))
    notes = load_jsonl(D / "bot" / "notifications.jsonl")
    stats = json.loads((D / "bot" / "llm_stats.json").read_text(encoding="utf-8"))

    anomalous = conv["eval"]["anomalous"]
    grades = Counter(a["grade"] for a in alerts)
    immediate = grades.get("심각", 0) + grades.get("경계", 0)
    by_host = Counter((a["asset_name"], a["grade"]) for a in alerts)
    checks = [fact_check(n) for n in notes]
    secs = [c["seconds"] for c in stats["calls"]]

    # 정렬 기준 비교: 이벤트 수(T만)로 정렬했을 때와 T×I×A로 정렬했을 때 즉시 알림 대상 구성
    k = immediate
    top_by_count = sorted(alerts, key=lambda a: -a["flow_count"])[:k]
    top_by_risk = sorted(alerts, key=lambda a: (-a["risk"], -a["flow_count"]))[:k]

    result = {
        "eval_events": conv["eval"]["events"],
        "eval_anomalous_events": anomalous,
        "eval_by_type": conv["eval"]["by_type"],
        "alerts": len(alerts),
        "events_per_alert": round(anomalous / len(alerts), 2),
        "grades": dict(grades),
        "immediate_alerts": immediate,
        "immediate_share": round(immediate / len(alerts), 3),
        "alerts_by_asset_grade": {f"{a} / {g}": n for (a, g), n in sorted(by_host.items())},
        "top_k_by_event_count_types": dict(Counter(a["impact_type"] for a in top_by_count)),
        "top_k_by_risk_types": dict(Counter(a["impact_type"] for a in top_by_risk)),
        "top_k_by_event_count_assets": dict(Counter(a["asset_name"] for a in top_by_count)),
        "top_k_by_risk_assets": dict(Counter(a["asset_name"] for a in top_by_risk)),
        "llm_model": stats["model"],
        "llm_calls": len(secs),
        "llm_avg_seconds": round(st.mean(secs), 2),
        "llm_max_seconds": round(max(secs), 2),
        "llm_avg_prompt_tokens": round(st.mean(c["prompt_tokens"] for c in stats["calls"])),
        "llm_avg_completion_tokens": round(st.mean(c["completion_tokens"] for c in stats["calls"])),
        "llm_fact_check_pass": sum(c["ok"] for c in checks),
        "llm_mentions_tia": sum(c["mentions_rationale"] for c in checks),
        "llm_fact_check": checks,
    }
    (D / "loghub_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    for key, v in result.items():
        if key != "llm_fact_check":
            print(f"{key}: {v}")
    for c in checks:
        if not c["ok"]:
            print("사실 불일치:", c)


if __name__ == "__main__":
    main()
