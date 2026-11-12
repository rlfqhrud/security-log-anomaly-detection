"""SIEM 등에서 내보낸 CSV/JSON 어댑터.

컬럼 이름이 제각각이므로 설정의 field_map으로 공통 스키마에 매핑한다.

    field_map:
      dst_ip: destination.ip            # 원본 필드 이름 (중첩 JSON은 점 표기)
      event_type: [rule.category, event.category]   # 목록이면 행마다 앞에서부터 처음 값이 있는 필드

- 형식: .csv / .json(배열 또는 객체) / .jsonl·.ndjson(줄 단위). format: auto면 확장자로 판단한다.
- 중첩 JSON은 pandas.json_normalize로 펼쳐 "destination.ip" 같은 이름이 된다.
- 필수: timestamp, dst_ip. 매핑한 필드가 파일에 아예 없으면 ValueError,
  일부 행만 비어 있으면 그 행을 경고와 함께 제외한다.
- event_type이 비어 있으면 default_event_type으로 채운다.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .base import first_present, finalize, join_listish, logger, resolve_paths, to_utc

SOURCE = "generic"
TIME_RESOLUTION = "1s"
REQUIRED = ("timestamp", "dst_ip")
FIELDS = ("timestamp", "src_ip", "dst_ip", "dst_port", "proto", "event_type",
          "severity_hint", "raw_ref", "signature")


def _read_one(path, fmt: str, encoding: str) -> pd.DataFrame:
    p = Path(path)
    if fmt == "auto":
        ext = p.suffix.lower()
        fmt = {".csv": "csv", ".tsv": "csv", ".jsonl": "jsonl", ".ndjson": "jsonl", ".json": "json"}.get(ext)
        if fmt is None:
            raise ValueError(f"형식을 알 수 없는 파일입니다(--input-format generic): {p.name}. input.generic.format을 지정하세요.")
    if fmt == "csv":
        df = pd.read_csv(p, encoding=encoding, low_memory=False, sep="\t" if p.suffix.lower() == ".tsv" else ",")
        df["_line"] = range(2, len(df) + 2)
        return df
    with open(p, encoding=encoding) as f:
        text = f.read()
    records, lines = [], []
    if fmt == "json":
        data = json.loads(text)
        if isinstance(data, dict):  # {"hits": [...]} 등 목록 하나를 감싼 객체
            lists = [v for v in data.values() if isinstance(v, list)]
            data = lists[0] if len(lists) == 1 else [data]
        records = list(data)
        lines = [i + 1 for i in range(len(records))]   # JSON 배열은 원소 순번
    else:
        for n, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                try:
                    records.append(json.loads(line))
                    lines.append(n)
                except json.JSONDecodeError:
                    logger.warning("[generic] %s:%d JSON으로 읽을 수 없어 건너뜁니다.", p.name, n)
    df = pd.json_normalize(records)
    df["_line"] = lines
    return df


def load_generic(paths, field_map: dict, timezone: str = "UTC", fmt: str = "auto",
                 encoding: str = "utf-8-sig", default_event_type: str = "Unknown",
                 filter: dict | None = None, keep=()) -> pd.DataFrame:
    """SIEM 내보내기 파일 → 공통 이벤트 스키마.

    filter: {"field": "event.kind", "values": ["alert", "signal"]} 처럼 주면 해당 행만 쓴다.
    keep  : 평가용으로 그대로 넘길 원본 컬럼(정답 레이블 등).
    """
    field_map = dict(field_map or {})
    unknown = set(field_map) - set(FIELDS)
    if unknown:
        raise ValueError(f"field_map에 알 수 없는 공통 필드가 있습니다: {sorted(unknown)} (가능: {FIELDS})")

    frames = []
    for path in resolve_paths(paths):
        raw = _read_one(path, fmt, encoding)
        name = Path(path).name
        for field in REQUIRED:
            if first_present(raw, field_map.get(field)) is None:
                raise ValueError(f"{name}: 필수 필드 '{field}'에 매핑된 원본 필드 {field_map.get(field)!r}가 없습니다. "
                                 f"config의 input.generic.field_map을 확인하세요. (원본 필드 예: {list(raw.columns)[:12]})")
        if filter:
            col = filter.get("field")
            if col not in raw.columns:
                raise ValueError(f"{name}: filter 필드 '{col}'가 없습니다.")
            raw = raw[raw[col].astype(str).isin([str(v) for v in filter.get("values", [])])]

        mapped = pd.DataFrame(index=raw.index)
        for field in FIELDS:
            values = first_present(raw, field_map.get(field))
            if values is not None:
                mapped[field] = join_listish(values)
        ev = mapped.get("event_type")
        if ev is None:
            mapped["event_type"] = default_event_type
        else:
            empty = ev.isna() | (ev.astype(str).str.strip() == "")
            mapped["event_type"] = ev.astype(object).where(~empty, default_event_type)
        ref = mapped.get("raw_ref")
        line_ref = name + ":" + raw["_line"].astype(str)
        mapped["raw_ref"] = line_ref if ref is None else (name + "#" + ref.astype(str)).where(ref.notna(), line_ref)
        mapped["timestamp"] = to_utc(mapped["timestamp"], timezone)
        for col in keep or ():
            if col in raw.columns:
                mapped[col] = raw[col]
        frames.append(mapped)

    df = pd.concat(frames, ignore_index=True)
    return finalize(df, SOURCE, keep=[c for c in (keep or ()) if c in df.columns])
