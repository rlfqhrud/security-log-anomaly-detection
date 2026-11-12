"""CICIDS2017 형식을 흉내 낸 합성 flow 데이터 생성기.

[경고] 이 데이터는 파이프라인이 끝까지 동작하는지 확인하기 위한 것이다.
       공격 강도, 분류기 혼동률, 오탐률은 모두 임의로 정한 값이므로
       여기서 나온 평가 결과를 논문 수치로 쓰면 안 된다.
       논문 실험은 실제 CICIDS2017 GeneratedLabelledFlows CSV와 실제 모델 판정으로 수행한다.

- seed 42, 화~금(2017-07-04~07) 09:00~16:59
- 분당 Poisson(120) 정상 flow → 웹서버·DC·Ubuntu12·사용자 PC
- UNB CIC 공개 공격 일정과 피해 자산을 따른다. 공격자 205.174.165.73
- 가상 분류기 혼동: XSS↔Brute Force, SQLi→Brute Force, Infiltration·Bot 일부 놓침, 정상 0.2% 오탐
- 원본 형식: 컬럼명 앞 공백, "6/7/2017 2:15" 같은 AM/PM 없는 12시간제,
  cp1252 en dash(0x96)로 저장된 "Web Attack – …" 레이블(UTF-8로 보면 "Web Attack � …")

실행: python examples/make_synthetic.py  → examples/data/calib_tue_wed.csv, eval_thu_fri.csv
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

SEED = 42
OUT_DIR = Path(__file__).resolve().parent / "data"

ATTACKER = "205.174.165.73"
WEB, DC, UBUNTU12 = "192.168.10.50", "192.168.10.3", "192.168.10.51"
PCS = ["192.168.10.19", "192.168.10.17", "192.168.10.16", "192.168.10.12", "192.168.10.9",
       "192.168.10.5", "192.168.10.8", "192.168.10.14", "192.168.10.15", "192.168.10.25"]
EXTERNAL = [f"52.{i}.{(i * 37) % 250}.{(i * 11) % 250 + 1}" for i in range(1, 21)]

DAYS = {"Tue": pd.Timestamp("2017-07-04"), "Wed": pd.Timestamp("2017-07-05"),
        "Thu": pd.Timestamp("2017-07-06"), "Fri": pd.Timestamp("2017-07-07")}

BENIGN = "BENIGN"
BF, XSS, SQLI = "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection"
ATTACK_TYPES = ["FTP-Patator", "SSH-Patator", "DoS slowloris", "DoS Slowhttptest", "DoS Hulk",
                "DoS GoldenEye", "Heartbleed", BF, XSS, SQLI, "Infiltration", "Bot", "PortScan", "DDoS"]

# (요일, 유형, 시작, 끝(미포함), 피해 IP 목록, 목적지 포트, 피해 IP당 분당 평균 flow, 분당 활동 확률)
# 시각은 UNB CIC 공개 일정 기준, 강도는 임의 값.
SCHEDULE = [
    ("Tue", "FTP-Patator", "09:20", "10:20", [WEB], 21, 60, 1.0),
    ("Tue", "SSH-Patator", "14:00", "15:00", [WEB], 22, 40, 1.0),
    ("Wed", "DoS slowloris", "09:47", "10:10", [WEB], 80, 40, 1.0),
    ("Wed", "DoS Slowhttptest", "10:14", "10:35", [WEB], 80, 40, 1.0),
    ("Wed", "DoS Hulk", "10:43", "11:00", [WEB], 80, 400, 1.0),
    ("Wed", "DoS GoldenEye", "11:10", "11:23", [WEB], 80, 150, 1.0),
    ("Wed", "Heartbleed", "15:12", "15:32", [UBUNTU12], 444, 0.6, 1.0),
    ("Thu", BF, "09:20", "10:00", [WEB], 80, 30, 1.0),
    ("Thu", XSS, "10:15", "10:35", [WEB], 80, 15, 1.0),
    ("Thu", SQLI, "10:40", "10:42", [WEB], 80, 7, 1.0),
    ("Thu", "Infiltration", "14:19", "14:21", ["192.168.10.8"], 444, 1.5, 1.0),
    ("Thu", "Infiltration", "14:33", "14:35", ["192.168.10.8"], 444, 1.5, 1.0),
    ("Thu", "Infiltration", "14:53", "15:00", ["192.168.10.25"], 444, 1.0, 1.0),
    ("Thu", "Infiltration", "15:04", "15:45", ["192.168.10.8"], 444, 1.0, 0.6),
    ("Fri", "Bot", "10:02", "11:02", ["192.168.10.15", "192.168.10.9", "192.168.10.14",
                                      "192.168.10.5", "192.168.10.8"], 8080, 2.0, 0.5),
    ("Fri", "PortScan", "13:55", "14:35", [WEB], 0, 200, 1.0),
    ("Fri", "DDoS", "15:56", "16:16", [WEB], 80, 500, 1.0),
]

# 가상 분류기 혼동 (정답 → [(예측, 확률), ...]); 나머지 확률은 정답 그대로
CONFUSION = {
    XSS: [(BF, 0.40)],
    BF: [(XSS, 0.15)],
    SQLI: [(BF, 0.30)],
    "Infiltration": [(BENIGN, 0.40)],
    "Bot": [(BENIGN, 0.30)],
}
OTHER_MISS = 0.02     # 위에 없는 공격 유형의 미탐률
BENIGN_FP = 0.002     # 정상 flow 오탐률

# 이상탐지 모델(kisa_scoring.detect) 학습용 flow 특징.
# 유형별 (Total Fwd Packets 평균, log10 Flow Packets/s 평균, Fwd Packet Length Mean 평균) — 임의 값.
# 웹 공격 3종은 일부러 비슷하게 두어 실제처럼 서로 헷갈리게 한다.
FEATURE_PROFILE = {
    BENIGN: (30, 0.8, 700),
    "FTP-Patator": (8, 2.6, 25),
    "SSH-Patator": (14, 2.4, 60),
    "DoS slowloris": (4, 0.3, 120),
    "DoS Slowhttptest": (3, 0.2, 100),
    "DoS Hulk": (6, 4.2, 350),
    "DoS GoldenEye": (7, 3.6, 330),
    "Heartbleed": (900, 3.0, 2000),
    BF: (5, 2.2, 180),
    XSS: (5, 2.1, 220),
    SQLI: (5, 2.0, 200),
    "Infiltration": (20, 1.5, 450),
    "Bot": (6, 1.8, 140),
    "PortScan": (1, 5.0, 2),
    "DDoS": (4, 4.6, 8),
}
FEATURE_SEED = 7      # 기존 컬럼 값이 바뀌지 않도록 특징은 별도 난수로 만든다


def _minutes(day: pd.Timestamp, start: str, end: str) -> pd.DatetimeIndex:
    return pd.date_range(day + pd.Timedelta(start + ":00"), day + pd.Timedelta(end + ":00"),
                         freq="1min", inclusive="left")


def _benign(rng: np.random.Generator, day: pd.Timestamp) -> pd.DataFrame:
    minutes = _minutes(day, "09:00", "17:00")
    counts = rng.poisson(120, len(minutes))
    n = int(counts.sum())
    ts = np.repeat(minutes.values, counts) + rng.integers(0, 60, n).astype("timedelta64[s]")
    dsts = np.array([WEB, DC, UBUNTU12] + PCS)
    p = np.array([0.40, 0.25, 0.05] + [0.30 / len(PCS)] * len(PCS))
    dst = rng.choice(dsts, n, p=p)
    src = rng.choice(np.array(PCS + EXTERNAL), n)
    src = np.where(src == dst, rng.choice(np.array(EXTERNAL), n), src)
    port = np.select([dst == WEB, dst == DC, dst == UBUNTU12],
                     [rng.choice([80, 443], n), 53, rng.choice([22, 80], n)],
                     default=rng.choice([443, 445, 139], n))
    return pd.DataFrame({"ts": ts, "src": src, "dst": dst, "dport": port, "label": BENIGN})


def _attacks(rng: np.random.Generator, day_name: str) -> pd.DataFrame:
    parts = []
    for day, label, start, end, victims, dport, rate, active in SCHEDULE:
        if day != day_name:
            continue
        minutes = _minutes(DAYS[day], start, end)
        for victim in victims:
            counts = rng.poisson(rate, len(minutes)) * (rng.random(len(minutes)) < active)
            n = int(counts.sum())
            if n == 0:
                continue
            ts = np.repeat(minutes.values, counts) + rng.integers(0, 60, n).astype("timedelta64[s]")
            port = rng.integers(1, 1024, n) if label == "PortScan" else np.full(n, dport)
            parts.append(pd.DataFrame({"ts": ts, "src": ATTACKER, "dst": victim, "dport": port, "label": label}))
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def _classify(rng: np.random.Generator, label: pd.Series) -> np.ndarray:
    """가상 분류기 판정."""
    y = label.to_numpy(dtype=object)
    pred = y.copy()
    u = rng.random(len(y))
    benign = y == BENIGN
    fp = benign & (u < BENIGN_FP)
    pred[fp] = rng.choice(np.array(ATTACK_TYPES, dtype=object), int(fp.sum()))
    handled = benign.copy()
    for truth, rules in CONFUSION.items():
        m = y == truth
        handled |= m
        lo = 0.0
        for to, prob in rules:
            pred[m & (u >= lo) & (u < lo + prob)] = to
            lo += prob
    pred[~handled & (u < OTHER_MISS)] = BENIGN
    return pred


def _raw_label(s: pd.Series) -> pd.Series:
    """원본처럼 "Web Attack – XSS"(cp1252 0x96으로 저장됨)로 바꾼다."""
    return s.str.replace("Web Attack - ", "Web Attack – ", regex=False)


def _format_ts(ts: pd.Series, twelve_hour: bool) -> pd.Series:
    """원본 형식 문자열. 12시간제는 AM/PM 없이 "6/7/2017 2:15", 아니면 "04/07/2017 14:15:09"."""
    if not twelve_hour:
        return ts.dt.strftime("%d/%m/%Y %H:%M:%S")
    hour = ts.dt.hour.where(ts.dt.hour <= 12, ts.dt.hour - 12)
    return (ts.dt.day.astype(str) + "/" + ts.dt.month.astype(str) + "/" + ts.dt.year.astype(str) + " "
            + hour.astype(str) + ":" + ts.dt.minute.astype(str).str.zfill(2))


def _features(rng: np.random.Generator, label: pd.Series) -> dict:
    """유형별 분포에서 flow 특징을 뽑는다. 분포가 겹치므로 모델이 100% 맞히지는 못한다."""
    prof = np.array([FEATURE_PROFILE.get(v, FEATURE_PROFILE[BENIGN]) for v in label], dtype=float)
    n = len(label)
    fwd = np.maximum(1, rng.poisson(prof[:, 0] * rng.lognormal(0, 0.5, n)))
    pps = 10 ** rng.normal(prof[:, 1], 0.4, n)
    plen = np.maximum(0, rng.normal(prof[:, 2], prof[:, 2] * 0.25 + 5, n))
    return {
        " Total Fwd Packets": fwd.astype(int),
        " Flow Packets/s": pps.round(3),
        " Fwd Packet Length Mean": plen.round(2),
    }


def make_day(rng: np.random.Generator, day_name: str, feat_rng: np.random.Generator | None = None) -> pd.DataFrame:
    df = pd.concat([_benign(rng, DAYS[day_name]), _attacks(rng, day_name)], ignore_index=True)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df["pred"] = _classify(rng, df["label"])
    n = len(df)
    sport = rng.integers(1024, 65535, n)
    out = pd.DataFrame({
        "Flow ID": df["dst"] + "-" + df["src"] + "-" + df["dport"].astype(str) + "-" + pd.Series(sport).astype(str) + "-6",
        " Source IP": df["src"],
        " Source Port": sport,
        " Destination IP": df["dst"],
        " Destination Port": df["dport"],
        " Protocol": 6,
        # 화요일은 24시간제·초 포함, 나머지는 AM/PM 없는 12시간제(원본 파일 간 형식 차이를 흉내)
        " Timestamp": _format_ts(df["ts"], twelve_hour=day_name != "Tue"),
        " Flow Duration": rng.integers(1, 5_000_000, n),
        **_features(feat_rng or np.random.default_rng(FEATURE_SEED), df["label"]),
        " Label": _raw_label(df["label"]),
        # 가상 분류기 판정. 실제 모델 판정은 python -m kisa_scoring.detect로 만든다.
        "pred": _raw_label(pd.Series(df["pred"], dtype=object)),
    })
    return out


def main() -> None:
    rng = np.random.default_rng(SEED)
    feat_rng = np.random.default_rng(FEATURE_SEED)
    days = {name: make_day(rng, name, feat_rng) for name in DAYS}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fname, names in [("calib_tue_wed.csv", ["Tue", "Wed"]), ("eval_thu_fri.csv", ["Thu", "Fri"])]:
        df = pd.concat([days[d] for d in names], ignore_index=True)
        path = OUT_DIR / fname
        df.to_csv(path, index=False, encoding="cp1252")
        attacks = (df[" Label"] != BENIGN).sum()
        print(f"{path}  rows={len(df):,}  attack_flows={attacks:,}")


if __name__ == "__main__":
    main()
