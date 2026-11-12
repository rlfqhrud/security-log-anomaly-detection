"""알림 전달 단계: 위험도 등급에 따라 알림봇 동작을 나눈다 (논문 표 2).

    심각 → LLM 상세 요약 + Discord 즉시 알림
    경계 → LLM 요약     + Discord 즉시 알림
    주의 → 정기 요약 보고서(periodic_report.md)에 포함
    관심 → 기록(alert_log.jsonl)만

등급별 동작은 설정 파일 등급표의 action 문구("즉시 알림 + LLM 상세 요약" 등)를 따른다.
DISCORD_WEBHOOK_URL이 없으면 Discord로 보내지 않고 화면에 출력한다(드라이런).

실행:
    python -m kisa_scoring.alert_bot --alerts results/alerts.json --out results/bot
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .llm_summary import Summarizer

IMMEDIATE, REPORT, LOG = "immediate", "report", "log"
GRADE_COLORS = {"심각": 0xD32F2F, "경계": 0xF57C00, "주의": 0xFBC02D, "관심": 0x9E9E9E}
DISCORD_LIMIT = 4000          # embed description 최대 4096자
USER_AGENT = "kisa-soc-alert-bot/1.0"


def route(record: dict) -> tuple[str, bool]:
    """(동작, 상세 요약 여부). 등급표 action 문구로 판단한다."""
    action = str(record.get("action") or "")
    if "즉시" in action:
        return IMMEDIATE, "상세" in action
    if "정기" in action or "보고" in action:
        return REPORT, False
    return LOG, False


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v)) or "-"
    return str(v).replace(";", ", ") if v else "-"


def discord_payload(record: dict, summary: str, method: str) -> dict:
    grade = record.get("grade", "")
    title = f"[{grade}] 위험도 {record.get('risk')} · {record.get('asset_name') or record.get('dst_ip')}"
    by = "LLM 요약" if method != "template" else "템플릿 요약(LLM 미사용)"
    return {
        "username": "SOC 알림봇",
        "embeds": [{
            "title": title[:256],
            "description": summary[:DISCORD_LIMIT],
            "color": GRADE_COLORS.get(grade, 0x607D8B),
            "fields": [
                {"name": "공격도 T", "value": str(record.get("T", "-")), "inline": True},
                {"name": "충격도 I", "value": str(record.get("I", "-")), "inline": True},
                {"name": "자산가치 A", "value": str(record.get("A", "-")), "inline": True},
                {"name": "목적지", "value": str(record.get("dst_ip", "-")), "inline": True},
                {"name": "시간 창", "value": str(record.get("window_start", "-")), "inline": True},
                {"name": "출발지", "value": _join(record.get("src_ips"))[:1024], "inline": False},
            ],
            "footer": {"text": f"KISA 위험도 = T×I×A · {by} ({method})"},
        }],
    }


def send_discord(url: str, payload: dict, retries: int = 3) -> bool:
    """Discord 웹훅 POST. 429(속도 제한)이면 retry_after만큼 기다렸다 다시 보낸다."""
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for _ in range(retries):
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as e:
            if e.code == 429:
                try:
                    wait = float(json.loads(e.read().decode("utf-8")).get("retry_after", 1.0))
                except Exception:
                    wait = 1.0
                time.sleep(min(wait, 30))
                continue
            print(f"[경고] Discord 전송 실패: HTTP {e.code}", file=sys.stderr)
            return False
        except urllib.error.URLError as e:
            print(f"[경고] Discord 전송 실패: {e.reason}", file=sys.stderr)
            return False
    return False


@dataclass
class BotResult:
    immediate: list[dict] = field(default_factory=list)
    report: list[dict] = field(default_factory=list)
    log: list[dict] = field(default_factory=list)
    skipped: int = 0


class AlertBot:
    def __init__(self, summarizer: Summarizer, webhook_url: str | None = None, sender=send_discord,
                 limit: int | None = None, echo=print):
        self.summarizer = summarizer
        self.webhook_url = webhook_url
        self.sender = sender
        self.limit = limit
        self.echo = echo

    def dispatch(self, records: list[dict]) -> BotResult:
        """records는 위험도 내림차순이라고 가정한다(alerts.json이 그렇게 저장됨)."""
        result = BotResult()
        records = sorted(records, key=lambda r: -(r.get("risk") or 0))
        for rec in records:
            kind, detailed = route(rec)
            if kind == IMMEDIATE:
                if self.limit is not None and len(result.immediate) >= self.limit:
                    result.skipped += 1
                    result.report.append(rec)   # 한도를 넘은 즉시 알림 대상은 보고서에라도 남긴다
                    continue
                summary, method = self.summarizer.summarize(rec, detailed=detailed)
                sent = None
                if self.webhook_url:
                    sent = self.sender(self.webhook_url, discord_payload(rec, summary, method))
                else:
                    self.echo(f"\n=== [{rec.get('grade')}] 위험도 {rec.get('risk')} · {rec.get('dst_ip')} ({method}) ===\n{summary}")
                result.immediate.append({**rec, "summary": summary, "summary_method": method,
                                         "detailed": detailed, "discord_sent": sent})
            elif kind == REPORT:
                result.report.append(rec)
            else:
                result.log.append(rec)
        return result


def periodic_report(records: list[dict], generated_at: str) -> str:
    lines = [
        "# 정기 요약 보고 (주의 등급 + 즉시 알림 한도 초과분)",
        "",
        f"생성 시각: {generated_at} · 경보 {len(records)}건",
        "",
        "| 시간 창 | 목적지 | 자산 | 유형 | flow 수 | T | I | A | 위험도 | 등급 |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in records:
        lines.append(
            f"| {r.get('window_start')} | {r.get('dst_ip')} | {r.get('asset_name')} | "
            f"{_join(r.get('impact_type') or r.get('attack_types'))} | {r.get('flow_count')} | "
            f"{r.get('T')} | {r.get('I', '-')} | {r.get('A')} | {r.get('risk')} | {r.get('grade')} |"
        )
    return "\n".join(lines) + "\n"


def save(result: BotResult, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "notifications.jsonl", "w", encoding="utf-8") as f:
        for r in result.immediate:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out / "periodic_report.md").write_text(
        periodic_report(result.report, datetime.now().strftime("%Y-%m-%d %H:%M:%S")), encoding="utf-8")
    with open(out / "alert_log.jsonl", "w", encoding="utf-8") as f:
        for r in result.log:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return out


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    p = argparse.ArgumentParser(prog="python -m kisa_scoring.alert_bot",
                                description="위험도 등급별 알림봇 (Discord 웹훅 + OpenAI GPT 요약)")
    p.add_argument("--alerts", required=True, help="python -m kisa_scoring이 만든 alerts.json")
    p.add_argument("--out", default="results/bot", help="알림 기록·보고서 출력 폴더")
    p.add_argument("--webhook", default=None, help="Discord 웹훅 URL (기본: 환경 변수 DISCORD_WEBHOOK_URL)")
    p.add_argument("--limit", type=int, default=None, help="즉시 알림 최대 건수 (시연용, 초과분은 보고서로)")
    p.add_argument("--no-llm", action="store_true", help="LLM을 쓰지 않고 템플릿 요약만 쓴다")
    p.add_argument("--model", default=None, help="OpenAI 모델 (기본: OPENAI_MODEL 또는 gpt-5.4-mini)")
    args = p.parse_args(argv)

    with open(args.alerts, encoding="utf-8") as f:
        records = json.load(f)
    webhook = args.webhook or os.environ.get("DISCORD_WEBHOOK_URL")
    summarizer = Summarizer(model=args.model, use_llm=not args.no_llm)
    if not summarizer.uses_llm and not args.no_llm:
        print("[안내] OPENAI_API_KEY가 없어 템플릿 요약을 씁니다.", file=sys.stderr)
    if not webhook:
        print("[안내] Discord 웹훅이 없어 화면에 출력합니다 (DISCORD_WEBHOOK_URL 또는 --webhook).", file=sys.stderr)

    result = AlertBot(summarizer, webhook_url=webhook, limit=args.limit).dispatch(records)
    out = save(result, args.out)
    if summarizer.stats:
        with open(out / "llm_stats.json", "w", encoding="utf-8") as f:
            json.dump({"model": summarizer.model, "calls": summarizer.stats}, f, ensure_ascii=False, indent=2)

    sent = sum(1 for r in result.immediate if r["discord_sent"])
    print(f"\n[알림봇] 경보 {len(records)}건")
    print(f"  즉시 알림(심각·경계): {len(result.immediate)}건" + (f" (Discord 전송 성공 {sent}건)" if webhook else " (화면 출력)"))
    if result.skipped:
        print(f"  --limit 초과로 보고서로 넘긴 즉시 알림 대상: {result.skipped}건")
    print(f"  정기 보고(주의): {len(result.report) - result.skipped}건 → {out / 'periodic_report.md'}")
    print(f"  기록(관심): {len(result.log)}건 → {out / 'alert_log.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
