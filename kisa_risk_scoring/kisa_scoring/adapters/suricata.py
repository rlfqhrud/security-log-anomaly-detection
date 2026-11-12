"""Suricata EVE JSON(줄 단위 JSON) 어댑터.

IDS가 이미 탐지한 결과이므로 이상탐지 모델을 거치지 않는다.
- event_type == "alert" 줄만 경보 입력으로 쓴다.
- flow 줄은 load_suricata_flows()로 따로 읽어 경보에 트래픽 맥락(건수)으로만 붙인다.
- dns, http, stats 등 나머지 줄은 무시한다.

매핑
  timestamp          → timestamp (EVE는 오프셋 포함 ISO 8601, 예: 2017-07-06T10:40:12.104713-0300)
  src_ip / dest_ip   → src_ip / dst_ip  (alert.source/target이 있으면 target을 피해 자산으로 본다)
  dest_port, proto   → dst_port, proto
  alert.category     → event_type (classtype 설명. 비어 있으면 "Unknown")
  alert.severity     → severity_hint (1=높음 … 3=낮음)
  alert.signature    → signature ("[sid:N]" 덧붙임)
  "파일명:줄번호"    → raw_ref
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .base import empty_events, finalize, logger, resolve_paths, to_utc

SOURCE = "suricata"
TIME_RESOLUTION = "1us"
UNKNOWN_CATEGORY = "Unknown"


def _iter_eve(path, wanted: set[str]):
    """(줄 번호, dict)를 낸다. 깨진 줄(로그 회전으로 잘린 마지막 줄 등)은 건너뛰고 경고한다."""
    bad = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(rec, dict) and rec.get("event_type") in wanted:
                yield lineno, rec
    if bad:
        logger.warning("[suricata] %s: JSON으로 읽을 수 없는 줄 %d개를 건너뜁니다.", Path(path).name, bad)


def _alert_row(name: str, lineno: int, rec: dict) -> dict:
    alert = rec.get("alert") or {}
    src, dst = rec.get("src_ip"), rec.get("dest_ip")
    dport = rec.get("dest_port")
    # Suricata 6+: 룰에 target 키워드가 있으면 alert.source/target이 붙는다. 피해 자산은 target.
    target, source = alert.get("target") or {}, alert.get("source") or {}
    if target.get("ip"):
        dst, dport = target["ip"], target.get("port", dport)
        src = source.get("ip", src)
    sig = alert.get("signature")
    sid = alert.get("signature_id")
    return {
        "timestamp": rec.get("timestamp"),
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": dport,
        "proto": rec.get("proto"),
        "event_type": (alert.get("category") or "").strip() or UNKNOWN_CATEGORY,
        "severity_hint": alert.get("severity"),
        "signature": f"{sig} [sid:{sid}]" if sig and sid is not None else sig,
        "raw_ref": f"{name}:{lineno}",
    }


def load_suricata(paths, timezone: str = "UTC") -> pd.DataFrame:
    """EVE 파일들의 alert 이벤트 → 공통 이벤트 스키마.

    timezone은 오프셋이 없는 시각에만 쓰인다(EVE는 보통 오프셋을 포함한다).
    """
    rows = []
    for p in resolve_paths(paths):
        name = Path(p).name
        rows += [_alert_row(name, n, rec) for n, rec in _iter_eve(p, {"alert"})]
    if not rows:
        logger.warning("[suricata] alert 이벤트가 없습니다: %s", [str(p) for p in resolve_paths(paths)])
        return empty_events()
    df = pd.DataFrame(rows)
    df["timestamp"] = to_utc(df["timestamp"], timezone)
    return finalize(df, SOURCE)


def load_suricata_flows(paths, timezone: str = "UTC") -> pd.DataFrame:
    """EVE flow 이벤트 → 공통 스키마(event_type="flow"). 경보 입력이 아니라 맥락 집계용이다.

    시각은 flow.start(없으면 timestamp)를 쓴다.
    """
    rows = []
    for p in resolve_paths(paths):
        name = Path(p).name
        for n, rec in _iter_eve(p, {"flow"}):
            flow = rec.get("flow") or {}
            rows.append({
                "timestamp": flow.get("start") or rec.get("timestamp"),
                "src_ip": rec.get("src_ip"), "dst_ip": rec.get("dest_ip"),
                "dst_port": rec.get("dest_port"), "proto": rec.get("proto"),
                "event_type": "flow", "raw_ref": f"{name}:{n}",
            })
    if not rows:
        return empty_events()
    df = pd.DataFrame(rows)
    df["timestamp"] = to_utc(df["timestamp"], timezone)
    return finalize(df, SOURCE)
