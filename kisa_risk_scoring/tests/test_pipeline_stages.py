"""이상탐지(detect) · LLM 요약(llm_summary) · 알림봇(alert_bot) 단계 테스트. 네트워크·API 키 없이 돈다."""
import json
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from kisa_scoring import alert_bot, detect, llm_summary

REC_SEVERE = {
    "window_start": "2017-07-06 10:40:00", "dst_ip": "192.168.10.50", "asset_name": "Web Server",
    "flow_count": 30, "impact_type": "Web Attack - Sql Injection", "attack_types": "Web Attack - Sql Injection",
    "T": 3, "I": 3, "A": 3, "risk": 27, "grade": "심각", "action": "즉시 알림 + LLM 상세 요약",
    "rationale": "위험도 27 = T×I×A; 공격도 T=3, 충격도 I=3, 자산가치 A=3", "src_ips": "205.174.165.73",
}
REC_WARN = {**REC_SEVERE, "risk": 18, "I": 2, "grade": "경계", "action": "즉시 알림 + LLM 요약",
            "impact_type": "DDoS", "attack_types": "DDoS"}
REC_CAUTION = {**REC_SEVERE, "risk": 6, "grade": "주의", "action": "정기 요약 보고에 포함"}
REC_INFO = {**REC_SEVERE, "risk": 2, "grade": "관심", "action": "기록"}


# ---------------------------------------------------------------- 알림봇 라우팅
@pytest.mark.parametrize("rec, expected", [
    (REC_SEVERE, (alert_bot.IMMEDIATE, True)),
    (REC_WARN, (alert_bot.IMMEDIATE, False)),
    (REC_CAUTION, (alert_bot.REPORT, False)),
    (REC_INFO, (alert_bot.LOG, False)),
])
def test_route_follows_grade_action(rec, expected):
    assert alert_bot.route(rec) == expected


def test_bot_sends_only_immediate_grades_to_discord():
    sent = []
    bot = alert_bot.AlertBot(llm_summary.Summarizer(use_llm=False), webhook_url="https://example/webhook",
                             sender=lambda url, payload: sent.append(payload) or True)
    result = bot.dispatch([REC_INFO, REC_CAUTION, REC_WARN, REC_SEVERE])
    assert [r["grade"] for r in result.immediate] == ["심각", "경계"]   # 위험도 내림차순
    assert result.immediate[0]["detailed"] and not result.immediate[1]["detailed"]
    assert len(sent) == 2 and sent[0]["embeds"][0]["title"].startswith("[심각]")
    assert [r["grade"] for r in result.report] == ["주의"]
    assert [r["grade"] for r in result.log] == ["관심"]


def test_bot_limit_moves_overflow_to_report(tmp_path):
    bot = alert_bot.AlertBot(llm_summary.Summarizer(use_llm=False), limit=1, echo=lambda *_: None)
    result = bot.dispatch([REC_WARN, REC_SEVERE, REC_CAUTION])
    assert len(result.immediate) == 1 and result.skipped == 1
    out = alert_bot.save(result, tmp_path)
    assert "주의" in (out / "periodic_report.md").read_text(encoding="utf-8")
    assert json.loads((out / "notifications.jsonl").read_text(encoding="utf-8"))["grade"] == "심각"


# ---------------------------------------------------------------- LLM 요약
def test_template_summary_uses_only_input_facts():
    text = llm_summary.template_summary(REC_SEVERE, detailed=True)
    assert REC_SEVERE["rationale"] in text
    assert "205.174.165.73" in text and "SQL 인젝션" in text   # 유형별 권장 조치


def test_prompt_contains_rationale_and_format():
    msgs = llm_summary.build_messages(REC_SEVERE, detailed=True)
    assert msgs[0]["role"] == "system"
    assert REC_SEVERE["rationale"] in msgs[1]["content"] and "추가 조사" in msgs[1]["content"]


class _FakeClient:
    def __init__(self, text=None, error=None):
        self.calls = []

        def create(**kw):
            self.calls.append(kw)
            if error:
                raise error
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])

        self.chat = SimpleNamespace(completions=SimpleNamespace(create=create))


def test_summarizer_calls_llm_and_falls_back_on_error():
    ok = llm_summary.Summarizer(client=_FakeClient("요약문"), model="gpt-test")
    assert ok.summarize(REC_WARN) == ("요약문", "gpt-test")
    assert ok.client.calls[0]["model"] == "gpt-test"

    bad = llm_summary.Summarizer(client=_FakeClient(error=RuntimeError("quota")))
    text, method = bad.summarize(REC_WARN)
    assert method == "template" and REC_WARN["rationale"] in text


# ---------------------------------------------------------------- 이상탐지
def _toy_flows(n_per_class=60, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for label, center in [("BENIGN", 0.0), ("DDoS", 5.0), ("PortScan", -5.0)]:
        for _ in range(n_per_class):
            rows.append({" Destination IP": "192.168.10.50", " Timestamp": "6/7/2017 9:00",
                         " Flow Packets/s": center + rng.normal(0, 0.5),
                         " Total Fwd Packets": center * 2 + rng.normal(0, 0.5),
                         " Label": label})
    return pd.DataFrame(rows)


def test_feature_columns_exclude_identifiers():
    cols = detect.feature_columns(_toy_flows(5))
    assert [c.strip() for c in cols] == ["Flow Packets/s", "Total Fwd Packets"]


def test_detect_run_writes_pred_and_metrics(tmp_path):
    src = tmp_path / "day.csv"
    _toy_flows().to_csv(src, index=False, encoding="latin-1")
    metrics = detect.run([str(src)], tmp_path / "out", folds=3)
    out = pd.read_csv(tmp_path / "out" / "day.csv", encoding="latin-1")
    assert "pred" in out.columns and len(out) == 180
    assert metrics["accuracy"] > 0.95 and metrics["binary_recall"] > 0.95
    assert (tmp_path / "out" / "detect_metrics.json").exists()
    assert (tmp_path / "out" / "feature_importance.csv").exists()
