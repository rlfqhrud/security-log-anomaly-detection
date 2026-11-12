"""CICIDS2017 플로우 통계 기반 DoS 룰: R-DOS-FLOOD / R-DOS-SLOW.

rules.py(세션 기반 라이브 데모 룰)와는 완전히 다른 입력 스키마(네트워크
플로우 통계: Destination Port, Flow Duration, Flow Packets/s)를 쓴다.
섞어 쓰지 않는다 - 이 모듈은 analyze_logs.py로 로드/정제한 CICIDS2017
DataFrame에 적용하는 용도다.

- R-DOS-FLOOD: 포트(기본 80) + 매우 높은 Flow Packets/s ("짧고 굵게",
  Hulk/GoldenEye류).
- R-DOS-SLOW: 포트(기본 80) + 긴 Flow Duration + 낮은 Flow Packets/s
  ("길고 가늘게", slowloris/Slowhttptest류).
- Flow Duration이 0이거나 Flow Packets/s가 inf/NaN인 행은 계산 오류
  가능성이 있으므로 두 룰 모두에서 제외한다 (DoS로 오탐하지 않음).

웹 공격(Brute Force/XSS/SQLi)은 플로우 통계만으로는 판단할 수 없다
(요청 payload가 없음). 억지로 판정하지 않고 web_attack_unavailable_notice()로
"판단 불가"를 명시적으로 알린다.

DRAFT: flow_rule_config.yaml의 임계값은 5주차 3단계 임계값 스윕(분위수
스윕 기반 precision/recall/F1 비교) 전 잠정값이다.
"""

from pathlib import Path

import numpy as np
import yaml

CONFIG_PATH = Path(__file__).resolve().parent / "flow_rule_config.yaml"


def _default_config():
    return {
        "dos_flood": {"port": 80, "min_flow_packets_per_sec": 1000},
        "dos_slow": {"port": 80, "min_flow_duration_us": 5_000_000, "max_flow_packets_per_sec": 10},
    }


def load_config(path=CONFIG_PATH):
    path = Path(path)
    if not path.exists():
        return _default_config()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if data else _default_config()


def _find_col(df, name):
    """공백 유무에 관계없이 컬럼을 찾는다 (analyze_logs.load_dataset을 거치면
    이미 strip 되어 있지만, 이 모듈을 독립적으로 쓸 때를 대비한 안전장치)."""
    name_norm = name.strip().lower()
    for col in df.columns:
        if col.strip().lower() == name_norm:
            return col
    raise KeyError(f"컬럼을 찾을 수 없음: {name!r}")


def _valid_rows(df, port_col, duration_col, pps_col):
    """Flow Duration이 0이거나 Flow Packets/s가 inf/NaN인 행은 신뢰할 수
    없으므로(0으로 나누기 등 계산 오류 가능성) DoS 판정 대상에서 제외한다."""
    pps_numeric = df[pps_col].astype(float)
    mask = (df[duration_col] > 0) & np.isfinite(pps_numeric)
    return df[mask]


def detect_dos_flood(df, config=None):
    """포트(기본 80) + 높은 Flow Packets/s 행을 DoS-Flood 후보로 표시한다."""
    cfg = (config or load_config())["dos_flood"]
    port_col = _find_col(df, "Destination Port")
    pps_col = _find_col(df, "Flow Packets/s")
    duration_col = _find_col(df, "Flow Duration")

    valid = _valid_rows(df, port_col, duration_col, pps_col)
    mask = (valid[port_col] == cfg["port"]) & (valid[pps_col] >= cfg["min_flow_packets_per_sec"])
    matched = valid[mask]

    return [
        {
            "rule": "dos_flood",
            "row_index": idx,
            "destination_port": int(row[port_col]),
            "flow_packets_per_sec": float(row[pps_col]),
            "detail": f"Destination Port={int(row[port_col])}, Flow Packets/s={row[pps_col]:.1f}",
        }
        for idx, row in matched.iterrows()
    ]


def detect_dos_slow(df, config=None):
    """포트(기본 80) + 긴 Flow Duration + 낮은 Flow Packets/s 행을
    DoS-Slow(slowloris류) 후보로 표시한다."""
    cfg = (config or load_config())["dos_slow"]
    port_col = _find_col(df, "Destination Port")
    pps_col = _find_col(df, "Flow Packets/s")
    duration_col = _find_col(df, "Flow Duration")

    valid = _valid_rows(df, port_col, duration_col, pps_col)
    mask = (
        (valid[port_col] == cfg["port"])
        & (valid[duration_col] >= cfg["min_flow_duration_us"])
        & (valid[pps_col] <= cfg["max_flow_packets_per_sec"])
    )
    matched = valid[mask]

    return [
        {
            "rule": "dos_slow",
            "row_index": idx,
            "destination_port": int(row[port_col]),
            "flow_duration_us": float(row[duration_col]),
            "flow_packets_per_sec": float(row[pps_col]),
            "detail": (
                f"Destination Port={int(row[port_col])}, "
                f"Flow Duration={row[duration_col] / 1_000_000:.1f}s, "
                f"Flow Packets/s={row[pps_col]:.2f}"
            ),
        }
        for idx, row in matched.iterrows()
    ]


def web_attack_unavailable_notice():
    """CICIDS2017 플로우 통계에는 payload/요청 내용이 없어 R-WEB-01
    (Brute Force/XSS/SQLi 시그니처)을 판단할 수 없다. 억지로 판정하지
    않고, 호출부가 명시적으로 "판단 불가"임을 알 수 있도록 이 함수를 쓴다."""
    return {
        "rule": "web_attack",
        "status": "판단_불가",
        "reason": (
            "CICIDS2017 플로우 통계(MachineLearningCVE)에는 HTTP 요청/쿼리스트링 같은 "
            "payload가 없어 SQLi/XSS/Brute Force 시그니처를 판단할 수 없습니다. "
            "payload가 있는 데이터(access log 등)가 있어야 R-WEB-01을 적용할 수 있습니다."
        ),
    }
