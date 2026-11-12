"""synthetic_cicids_sample.csv를 생성하는 스크립트.

실제 CICIDS2017 데이터가 아니다. MachineLearningCVE의 79컬럼 스키마(컬럼명의
leading space 포함)를 그대로 흉내 내고, analyze_logs.py가 잡아야 할 결함
케이스(중복행 / inf / NaN / 음수 / Init_Win_bytes의 -1 / 상수 컬럼 / 깨진
Label 문자)를 의도적으로 섞어 넣은 합성 데이터다. 실제 데이터 검증을
대체하지 않는다 - 스크립트 로직이 기계적으로 도는지만 확인하는 용도.
"""

from pathlib import Path

import numpy as np
import pandas as pd

COLUMNS = [
    "Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
    " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
    " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean",
    " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
    " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags",
    " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length",
    "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
    " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count",
    " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count",
    " URG Flag Count", " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio",
    " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size",
    " Fwd Header Length.1", "Fwd Avg Bytes/Bulk", " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes",
    "Init_Win_bytes_forward", " Init_Win_bytes_backward", " act_data_pkt_fwd",
    " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min",
    "Idle Mean", " Idle Std", " Idle Max", " Idle Min", " Label",
]

FEATURE_COLS = COLUMNS[:-1]  # Label 제외 78개


def _base_row(dst_port, label, flow_duration=100000, pps=50.0, bps=1000.0):
    row = {c: 0 for c in FEATURE_COLS}
    row["Destination Port"] = dst_port
    row[" Flow Duration"] = flow_duration
    row[" Total Fwd Packets"] = 10
    row[" Total Backward Packets"] = 8
    row["Flow Bytes/s"] = bps
    row[" Flow Packets/s"] = pps
    row[" Flow IAT Mean"] = 500.0
    row[" Flow IAT Min"] = 10.0
    row["Init_Win_bytes_forward"] = 8192
    row[" Init_Win_bytes_backward"] = 8192
    row[" Bwd PSH Flags"] = 0  # 의도적으로 전부 0 -> 상수 컬럼 테스트
    row[" Label"] = label
    return row


def build_rows():
    rows = []

    # 정상 트래픽 (중복 1쌍 포함)
    normal = _base_row(443, "BENIGN")
    rows.append(dict(normal))
    rows.append(dict(normal))  # 완전 중복행

    for _ in range(3):
        rows.append(_base_row(80, "BENIGN", flow_duration=200000, pps=20.0, bps=800.0))

    # DoS Hulk: 포트 80, 높은 pps
    for _ in range(3):
        rows.append(_base_row(80, "DoS Hulk", flow_duration=50000, pps=5000.0, bps=900000.0))

    # Flow Duration이 0이라 Flow Bytes/s, Flow Packets/s가 inf가 되는 비정상 케이스
    inf_row = _base_row(80, "DoS Hulk", flow_duration=0, pps=np.inf, bps=np.inf)
    rows.append(inf_row)

    # DoS Slowloris: 포트 80, 연결을 오래 쥐고 있지만 패킷은 거의 안 보냄
    # ("길고 가늘게" - R-DOS-SLOW가 잡아야 하는 패턴)
    for _ in range(2):
        rows.append(_base_row(80, "DoS Slowloris", flow_duration=8_000_000, pps=2.0, bps=50.0))

    # PortScan: 다양한 목적지 포트
    for port in (21, 22, 23, 139, 445):
        rows.append(_base_row(port, "PortScan", flow_duration=1000, pps=2.0, bps=100.0))

    # FTP-Patator (브루트포스 계열)
    for _ in range(2):
        rows.append(_base_row(21, "FTP-Patator", flow_duration=3000, pps=3.0, bps=150.0))

    # 희소 클래스: Heartbleed 1건만
    rows.append(_base_row(444, "Heartbleed", flow_duration=900000, pps=1.0, bps=50.0))

    # 라벨이 깨진 문자로 들어온 웹 공격 케이스 (실제 CICIDS2017에서 흔한 패턴)
    xss_row = _base_row(80, "Web Attack � XSS", flow_duration=4000, pps=4.0, bps=200.0)
    rows.append(xss_row)
    sqli_row = _base_row(80, "Web Attack � Sql Injection", flow_duration=4200, pps=4.0, bps=210.0)
    rows.append(sqli_row)

    # NaN 값이 섞인 행 (센서 결측 상황 흉내)
    nan_row = _base_row(80, "BENIGN", flow_duration=15000, pps=15.0, bps=400.0)
    nan_row[" Flow IAT Std"] = np.nan
    rows.append(nan_row)

    # 데이터 오류로 인한 음수값 (Init_Win_bytes_* 제외 컬럼에 발생한 이상치)
    neg_row = _base_row(80, "BENIGN", flow_duration=12000, pps=12.0, bps=300.0)
    neg_row[" Flow IAT Min"] = -50.0
    rows.append(neg_row)

    # Init_Win_bytes_forward = -1 (정상 센티널, 음수 이상치로 취급하면 안 됨)
    sentinel_row = _base_row(8080, "BENIGN", flow_duration=8000, pps=8.0, bps=250.0)
    sentinel_row["Init_Win_bytes_forward"] = -1
    sentinel_row[" Init_Win_bytes_backward"] = -1
    rows.append(sentinel_row)

    return rows


def main():
    rows = build_rows()
    df = pd.DataFrame(rows, columns=COLUMNS)
    out_path = Path(__file__).resolve().parent / "synthetic_cicids_sample.csv"
    df.to_csv(out_path, index=False)
    print(f"생성됨: {out_path} ({len(df)}행)")


if __name__ == "__main__":
    main()
