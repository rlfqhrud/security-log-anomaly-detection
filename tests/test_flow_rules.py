"""flow_rules.py 테스트: CICIDS2017 스키마 기반 R-DOS-FLOOD/R-DOS-SLOW.

합성 데이터(tests/fixtures/synthetic_cicids_sample.csv) 기준 동작 확인.
실제 CICIDS2017로 검증된 precision/recall이 아니다.
"""

from pathlib import Path

import pandas as pd

from analyze_logs import clean_dataset, load_dataset
from flow_rules import (
    detect_dos_flood,
    detect_dos_slow,
    load_config,
    web_attack_unavailable_notice,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "synthetic_cicids_sample.csv"


def _cleaned_fixture():
    return clean_dataset(load_dataset(FIXTURE))


def test_dos_flood_matches_only_high_pps_port80_rows():
    df = _cleaned_fixture()
    hits = detect_dos_flood(df)

    assert len(hits) == 1
    matched_label = df.loc[hits[0]["row_index"], "Label"]
    assert matched_label == "DoS Hulk"
    assert hits[0]["destination_port"] == 80
    assert "Flow Packets/s=5000.0" in hits[0]["detail"]


def test_dos_slow_matches_only_long_duration_low_pps_port80_rows():
    df = _cleaned_fixture()
    hits = detect_dos_slow(df)

    assert len(hits) == 1
    matched_label = df.loc[hits[0]["row_index"], "Label"]
    assert matched_label == "DoS Slowloris"
    assert "Flow Duration=8.0s" in hits[0]["detail"]


def test_dos_rules_do_not_flag_benign_or_other_attack_labels():
    df = _cleaned_fixture()
    flood_hits = detect_dos_flood(df)
    slow_hits = detect_dos_slow(df)

    flagged_labels = {df.loc[h["row_index"], "Label"] for h in flood_hits + slow_hits}
    assert flagged_labels == {"DoS Hulk", "DoS Slowloris"}


def test_zero_duration_or_inf_pps_rows_excluded_even_if_otherwise_matching():
    # 합성 데이터의 inf_row: port=80, flow_duration=0, pps=inf, label=DoS Hulk.
    # 정제 과정에서 inf/duration=0이 NaN이 되므로, 애초에 flood 조건
    # (pps >= 임계값)을 만족할 수 없다 -> 유일한 flood 매치는 진짜 DoS Hulk 1건뿐.
    df = _cleaned_fixture()
    inf_rows = df[(df["Label"] == "DoS Hulk") & (df["Flow Duration"].isna() | (df["Flow Duration"] == 0))]
    assert len(inf_rows) >= 1  # 합성 데이터에 해당 케이스가 실제로 존재하는지 확인

    hits = detect_dos_flood(df)
    assert len(hits) == 1  # inf_row는 매치되지 않음


def test_custom_config_changes_matches():
    df = _cleaned_fixture()
    # 임계값을 극단적으로 올리면 아무것도 안 잡혀야 한다
    strict_config = {"dos_flood": {"port": 80, "min_flow_packets_per_sec": 1_000_000}}
    assert detect_dos_flood(df, config=strict_config) == []


def test_load_config_falls_back_when_file_missing(tmp_path):
    config = load_config(tmp_path / "does_not_exist.yaml")
    assert config["dos_flood"]["port"] == 80
    assert config["dos_slow"]["port"] == 80


def test_web_attack_unavailable_notice_is_explicit_not_a_guess():
    notice = web_attack_unavailable_notice()
    assert notice["status"] == "판단_불가"
    assert "payload" in notice["reason"]


def test_empty_dataframe_produces_no_hits():
    df = _cleaned_fixture()
    empty = df.iloc[0:0]
    assert detect_dos_flood(empty) == []
    assert detect_dos_slow(empty) == []
