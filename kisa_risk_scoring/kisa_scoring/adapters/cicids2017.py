"""CICIDS2017 GeneratedLabelledFlows(TrafficLabelling) CSV 어댑터.

flow 하나가 이벤트 하나이고, 이상탐지 모델의 판정 컬럼(pred)이 event_type이 된다.
원본 시각은 timezone 없는 현지 시각(캐나다 대서양 시간)이므로 input.timezone으로 해석한다.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import pandas as pd

from .base import BENIGN, finalize, to_utc

SOURCE = "cicids2017"
TIME_RESOLUTION = "1min"   # 일부 파일이 분 단위로만 기록됨

# 원본 컬럼명(소문자, 앞뒤 공백 제거) → 내부 컬럼명
COLUMN_MAP = {
    "destination ip": "dst_ip",
    "source ip": "src_ip",
    "destination port": "dst_port",
    "timestamp": "timestamp",
    "label": "label",
}

# "Web Attack � Brute Force", "Web Attack – XSS", "Web Attack \x96 XSS" 등
# 깨진 구분 문자(영숫자·공백이 아닌 문자 1개 이상)를 "Web Attack - "로 통일한다.
_WEB_ATTACK_RE = re.compile(r"^web\s*attack\s*[^a-z0-9\s]+\s*", re.IGNORECASE)
_SPACES_RE = re.compile(r"\s+")

_MLCSV_HINT = (
    "CICIDS2017 MachineLearningCSV에는 Source/Destination IP와 Timestamp가 없습니다. "
    "GeneratedLabelledFlows(TrafficLabelling) CSV를 사용하세요."
)


def _normalize_one(value) -> str:
    if value is None or (not isinstance(value, str) and pd.isna(value)):
        return BENIGN
    s = _SPACES_RE.sub(" ", str(value)).strip()
    if not s or s.upper() == BENIGN:
        return BENIGN
    m = _WEB_ATTACK_RE.match(s)
    if m:
        s = "Web Attack - " + s[m.end():]
    return s


def normalize_label(value):
    """레이블 하나 또는 Series를 정규화한다.

    - 깨진 구분 문자 → "Web Attack - "
    - 연속 공백 정리, 앞뒤 공백 제거
    - 결측·빈 문자열·대소문자가 다른 BENIGN → "BENIGN"
    """
    if isinstance(value, pd.Series):
        return value.map(_normalize_one).astype(object)
    return _normalize_one(value)


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """컬럼명 앞뒤 공백을 제거하고 주요 컬럼을 내부 이름으로 바꾼다."""
    rename = {}
    for col in df.columns:
        stripped = str(col).strip()
        rename[col] = COLUMN_MAP.get(stripped.lower(), stripped)
    return df.rename(columns=rename)


def parse_timestamp(series: pd.Series, fix_12h: bool = True) -> pd.Series:
    """일/월/년 순서의 Timestamp를 파싱한다(결과는 timezone 없는 현지 시각).

    원본 일부 파일은 오후 시각을 AM/PM 없이 12시간제로 기록한다(예: 15:12 → "3:12").
    수집 시간이 09:00~17:00이므로 fix_12h가 켜져 있으면 1~7시를 13~19시로 보정한다.
    """
    ts = pd.to_datetime(series, dayfirst=True, format="mixed", errors="coerce")
    if fix_12h:
        afternoon = ts.dt.hour.between(1, 7)
        ts = ts.mask(afternoon, ts + pd.Timedelta(hours=12))
    return ts


def standardize(df: pd.DataFrame, fix_12h: bool = True, source: str = "") -> pd.DataFrame:
    """컬럼명 정규화, 필수 컬럼 확인, Timestamp 파싱, 레이블·IP 정리."""
    df = normalize_columns(df)
    missing = [c for c in ("dst_ip", "timestamp") if c not in df.columns]
    if missing:
        where = f" ({source})" if source else ""
        raise ValueError(f"필수 컬럼 {missing}이 없습니다{where}. {_MLCSV_HINT}")
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = parse_timestamp(df["timestamp"], fix_12h=fix_12h)
    for col in ("dst_ip", "src_ip"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip()
    if "label" in df.columns:
        df["label"] = normalize_label(df["label"])
    return df


def read_csv(path: str | Path, fix_12h: bool = True) -> pd.DataFrame:
    """CSV 하나를 원본 인코딩(latin-1)으로 읽어 표준화한다.

    raw_ref 컬럼에 "파일명:줄번호"(헤더 = 1행)를 기록해 경보 근거를 원본까지 추적할 수 있게 한다.
    """
    raw = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df = standardize(raw, fix_12h=fix_12h, source=str(path))
    if "raw_ref" not in df.columns:
        df["raw_ref"] = Path(path).name + ":" + pd.Series(range(2, len(df) + 2), index=df.index).astype(str)
    return df


def load_cicids2017(paths: str | Path | Iterable[str | Path], fix_12h: bool = True) -> pd.DataFrame:
    """여러 CICIDS2017 CSV를 읽어 정규화하고 합친 뒤 timestamp 순으로 정렬한다."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    frames = [read_csv(p, fix_12h=fix_12h) for p in paths]
    if not frames:
        raise ValueError("읽을 CSV 경로가 없습니다.")
    df = pd.concat(frames, ignore_index=True)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def to_events(df: pd.DataFrame, pred_col: str = "pred", timezone: str = "America/Moncton",
              keep: Iterable[str] = ("label",), require_labels: bool = False) -> pd.DataFrame:
    """표준화된 CICIDS2017 flow 표 → 공통 이벤트 스키마.

    - event_type: 판정 컬럼. 문자열이면 normalize_label, bool·숫자면 "Anomaly"/"BENIGN"
    - timestamp : timezone 없는 시각은 timezone으로 해석
    - keep      : 평가용으로 그대로 넘길 컬럼(정답 레이블 등)
    """
    missing = [c for c in ("timestamp", "dst_ip", pred_col) if c not in df.columns]
    if missing:
        raise ValueError(f"필수 컬럼이 없습니다: {missing}")
    pred = df[pred_col]
    numeric = pd.api.types.is_bool_dtype(pred) or pd.api.types.is_numeric_dtype(pred)
    if numeric and require_labels:
        raise ValueError(f"multiclass 모드에는 유형 레이블이 필요합니다. '{pred_col}'이 bool/숫자이면 binary 모드를 쓰세요.")
    if numeric:
        anomalous = pred.fillna(0).astype(float) != 0
        event_type = anomalous.map({True: "Anomaly", False: BENIGN})
    else:
        event_type = normalize_label(pred)

    ts = df["timestamp"]
    if not pd.api.types.is_datetime64_any_dtype(ts):
        ts = pd.to_datetime(ts)
    frame = pd.DataFrame({
        "timestamp": to_utc(ts, timezone),
        "src_ip": df["src_ip"] if "src_ip" in df.columns else None,
        "dst_ip": df["dst_ip"],
        "event_type": event_type,
        "raw_ref": df["raw_ref"] if "raw_ref" in df.columns else "row:" + pd.Series(df.index, index=df.index).astype(str),
    }, index=df.index)
    if "dst_port" in df.columns:
        frame["dst_port"] = df["dst_port"]
    for col in ("Protocol", "protocol"):
        if col in df.columns:
            frame["proto"] = df[col]
            break
    keep = [c for c in dict.fromkeys(keep) if c in df.columns and c not in frame.columns]
    for c in keep:
        frame[c] = df[c]
    return finalize(frame, SOURCE, keep=keep)
