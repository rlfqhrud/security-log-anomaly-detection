"""공통 이벤트 스키마와 어댑터 공용 도구.

모든 입력(CICIDS2017 flow, Suricata EVE, SIEM 내보내기)은 아래 컬럼을 가진 DataFrame으로 정규화된다.
scoring.py는 이 스키마만 본다.

| 컬럼          | 형식                         | 설명                                          |
|---------------|------------------------------|-----------------------------------------------|
| timestamp     | datetime64[ns, UTC]          | 이벤트 시각 (timezone 포함, 초 단위 이상)     |
| src_ip        | str | None                   | 출발지 IP (IPv6는 축약형, IPv4-mapped는 IPv4) |
| dst_ip        | str                          | 목적지(피해 자산) IP — 경보 집계 기준         |
| dst_port      | Int64 (nullable)             | 목적지 포트                                   |
| proto         | str | None                   | TCP / UDP / ICMP …                            |
| event_type    | str                          | 공격 유형 또는 탐지 규칙 분류. BENIGN = 정상  |
| severity_hint | object | None                | 원본 로그의 심각도 값                         |
| source        | str                          | cicids2017 / suricata / generic               |
| raw_ref       | str                          | 원본 줄 번호나 이벤트 ID (근거 추적용)        |

선택 컬럼: signature(탐지 규칙 이름) 및 평가용 정답 컬럼(예: label).
"""
from __future__ import annotations

import ipaddress
import logging
import re

import numpy as np
import pandas as pd

logger = logging.getLogger("kisa_scoring")

BENIGN = "BENIGN"
SCHEMA_COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port", "proto",
                  "event_type", "severity_hint", "source", "raw_ref"]
OPTIONAL_COLUMNS = ["signature"]
SOURCES = ("cicids2017", "suricata", "generic")

_PROTO_NUM = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "IPV6-ICMP", 132: "SCTP"}
_SPACES_RE = re.compile(r"\s+")
# 시각 뒤에 붙은 타임존 표기: Z, UTC, +09:00, -0300, +09
_TZ_SUFFIX_RE = r"\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?\s*(?:Z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)$"


def clean_text(series: pd.Series) -> pd.Series:
    """연속 공백 정리. 결측은 None."""
    return series.map(lambda v: None if v is None or (not isinstance(v, (list, dict)) and pd.isna(v))
                      else _SPACES_RE.sub(" ", str(v)).strip() or None).astype(object)


def _normalize_ip_one(value):
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return None
    s = str(value).strip().strip("[]")
    if not s:
        return None
    s = s.split("%", 1)[0]  # IPv6 zone id (fe80::1%eth0)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return s
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def normalize_ip(series: pd.Series) -> pd.Series:
    """IP 문자열 정규화: IPv6 축약형·소문자, IPv4-mapped IPv6 → IPv4. 형식이 틀리면 원문 유지."""
    uniq = pd.unique(series.astype(object))
    mapping = {v: _normalize_ip_one(v) for v in uniq}
    return series.astype(object).map(mapping).astype(object)


def normalize_proto(series: pd.Series) -> pd.Series:
    def one(v):
        if v is None or (not isinstance(v, str) and pd.isna(v)):
            return None
        s = str(v).strip()
        if s.isdigit():
            return _PROTO_NUM.get(int(s), s)
        return s.upper() or None
    return series.map(one).astype(object)


def to_utc(series: pd.Series, assume_tz: str, dayfirst: bool = False) -> pd.Series:
    """시각 값을 UTC tz-aware로 바꾼다.

    - 숫자: epoch (1e11보다 크면 ms, 아니면 s)
    - 타임존이 붙은 문자열(Z, +09:00, -0300): 그 오프셋을 따른다
    - 타임존이 없는 문자열: assume_tz로 해석한다
    한 열에 세 형태가 섞여 있어도 행마다 따로 처리한다. 파싱 실패는 NaT.
    """
    if pd.api.types.is_datetime64_any_dtype(series):
        ts = series
        if ts.dt.tz is None:
            ts = ts.dt.tz_localize(assume_tz, ambiguous="NaT", nonexistent="shift_forward")
        return ts.dt.tz_convert("UTC").dt.as_unit("ns")
    if pd.api.types.is_numeric_dtype(series):
        unit = "ms" if series.abs().max() > 1e11 else "s"
        return pd.to_datetime(series, unit=unit, utc=True, errors="coerce").dt.as_unit("ns")

    s = series.astype("string").str.strip()
    aware = s.str.contains(_TZ_SUFFIX_RE, regex=True, na=False).to_numpy()
    parts = []
    if aware.any():
        parts.append(pd.to_datetime(s[aware], format="mixed", dayfirst=dayfirst, utc=True, errors="coerce"))
    if (~aware).any():
        naive = pd.to_datetime(s[~aware], format="mixed", dayfirst=dayfirst, errors="coerce")
        if naive.dt.tz is None:
            naive = naive.dt.tz_localize(assume_tz, ambiguous="NaT", nonexistent="shift_forward")
        parts.append(naive.dt.tz_convert("UTC"))
    out = pd.concat([p.dt.as_unit("ns") for p in parts]).reindex(series.index)
    return out.astype("datetime64[ns, UTC]")


def finalize(df: pd.DataFrame, source: str, keep: list[str] | None = None) -> pd.DataFrame:
    """어댑터 결과를 공통 스키마로 마무리한다: 컬럼 채우기, 형 변환, 무효 행 제거(경고)."""
    out = pd.DataFrame(index=df.index)
    out["timestamp"] = df["timestamp"]
    out["src_ip"] = normalize_ip(df["src_ip"]) if "src_ip" in df else None
    out["dst_ip"] = normalize_ip(df["dst_ip"])
    out["dst_port"] = (pd.to_numeric(df["dst_port"], errors="coerce").astype("Int64")
                       if "dst_port" in df else pd.Series(pd.NA, index=df.index, dtype="Int64"))
    out["proto"] = normalize_proto(df["proto"]) if "proto" in df else None
    out["event_type"] = df["event_type"].astype(object)
    out["severity_hint"] = df["severity_hint"].astype(object) if "severity_hint" in df else None
    out["source"] = source
    out["raw_ref"] = df["raw_ref"].astype(str) if "raw_ref" in df else [f"{source}:row{i}" for i in range(len(df))]
    for col in OPTIONAL_COLUMNS + list(keep or []):
        if col in df.columns and col not in out.columns:
            out[col] = df[col]

    bad_ts = out["timestamp"].isna()
    bad_ip = out["dst_ip"].isna()
    if bad_ts.any():
        logger.warning("[%s] 시각을 해석할 수 없는 이벤트 %d건을 제외합니다 (예: %s)",
                       source, int(bad_ts.sum()), out.loc[bad_ts, "raw_ref"].head(3).tolist())
    if (bad_ip & ~bad_ts).any():
        logger.warning("[%s] 목적지 IP가 없는 이벤트 %d건을 제외합니다 (예: %s)",
                       source, int((bad_ip & ~bad_ts).sum()), out.loc[bad_ip & ~bad_ts, "raw_ref"].head(3).tolist())
    out = out[~(bad_ts | bad_ip)]
    return out.sort_values("timestamp", kind="stable").reset_index(drop=True)


def empty_events() -> pd.DataFrame:
    df = pd.DataFrame({c: pd.Series(dtype=object) for c in SCHEMA_COLUMNS})
    return df.astype({"timestamp": "datetime64[ns, UTC]", "dst_port": "Int64"})


def validate_events(df: pd.DataFrame) -> None:
    """공통 스키마를 만족하는지 확인한다."""
    missing = [c for c in SCHEMA_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"공통 이벤트 스키마 컬럼이 없습니다: {missing}")
    if not (pd.api.types.is_datetime64_any_dtype(df["timestamp"]) and getattr(df["timestamp"].dt, "tz", None)):
        raise ValueError("공통 스키마의 timestamp는 timezone 포함 datetime이어야 합니다.")


def resolve_paths(paths) -> list:
    if isinstance(paths, (str, bytes)) or hasattr(paths, "__fspath__"):
        return [paths]
    return list(paths)


def first_present(frame: pd.DataFrame, candidates) -> pd.Series | None:
    """후보 컬럼들을 앞에서부터 행마다 채운다(coalesce). 하나도 없으면 None."""
    if candidates is None:
        return None
    if isinstance(candidates, str):
        candidates = [candidates]
    cols = [c for c in candidates if c in frame.columns]
    if not cols:
        return None
    out = frame[cols[0]].astype(object)
    for c in cols[1:]:
        out = out.where(out.notna(), frame[c].astype(object))
    return out


def join_listish(series: pd.Series) -> pd.Series:
    """ECS의 event.category처럼 배열인 값은 ','로 잇는다."""
    return series.map(lambda v: ",".join(map(str, v)) if isinstance(v, (list, tuple, np.ndarray)) else v)
