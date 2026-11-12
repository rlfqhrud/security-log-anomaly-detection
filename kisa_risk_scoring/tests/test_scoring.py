import json

import pandas as pd
import pytest

from conftest import DC, UNREGISTERED, WEB
from kisa_scoring import RiskScorer, ScoringConfig, normalize_label, parse_timestamp

SQLI = "Web Attack - Sql Injection"


def test_1_normalize_label():
    assert normalize_label("Web Attack � Brute Force") == "Web Attack - Brute Force"
    assert normalize_label("Web Attack – XSS") == "Web Attack - XSS"
    assert normalize_label(" BENIGN ") == "BENIGN"
    s = normalize_label(pd.Series(["benign", None, "Web Attack \x96 Sql  Injection"]))
    assert s.tolist() == ["BENIGN", "BENIGN", SQLI]


def test_2_parse_timestamp_12h():
    ts = parse_timestamp(pd.Series(["5/7/2017 9:47", "5/7/2017 3:12"]))
    assert ts[0] == pd.Timestamp("2017-07-05 09:47")
    assert ts[1] == pd.Timestamp("2017-07-05 15:12")


def test_3_sqli_on_web_server_is_critical(make_scorer, flows):
    df = flows([(f"2017-07-06 10:40:{s:02d}", WEB, SQLI, SQLI) for s in range(0, 60, 10)])
    a = make_scorer().score(df).iloc[0]
    assert (a["T"], a["I"], a["A"], a["risk"], a["grade"]) == (3, 3, 3, 27, "심각")


def test_4_mixed_types_impact_and_count(make_scorer, flows):
    df = flows([
        ("2017-07-07 14:00:01", WEB, "PortScan", "PortScan"),
        ("2017-07-07 14:00:02", WEB, "DDoS", "DDoS"),
        ("2017-07-07 14:00:03", WEB, "BENIGN", "BENIGN"),
    ])
    alerts = make_scorer().score(df)
    assert len(alerts) == 1
    a = alerts.iloc[0]
    assert (a["flow_count"], a["I"], a["T"]) == (2, 2, 1)


def test_5_unregistered_ip_separate_windows(make_scorer, flows):
    df = flows([
        ("2017-07-07 14:00:10", UNREGISTERED, "PortScan", "PortScan"),
        ("2017-07-07 14:01:10", UNREGISTERED, "PortScan", "PortScan"),
    ])
    alerts = make_scorer().score(df)
    assert len(alerts) == 2
    assert (alerts["A"] == 1).all() and (alerts["risk"] == 1).all()
    assert (alerts["asset_name"] == "미등록 자산").all()


def test_6_binary_mode(make_scorer, flows):
    df = flows([(f"2017-07-05 11:00:0{i}", DC, p, p) for i, p in enumerate(["DoS", "DoS", "DoS", "BENIGN"])])
    df["pred"] = [1, 1, 1, 0]
    a = make_scorer("binary").score(df).iloc[0]
    assert (a["T"], a["A"], a["risk"], a["grade"]) == (2, 3, 6, "경계")
    assert pd.isna(a["I"]) and pd.isna(a["impact_type"])


def test_7_quantile_fit(flows):
    rows = []
    for minute, n in enumerate([1, 1, 2, 3, 5, 8, 13, 40]):
        rows += [(f"2017-07-04 09:{minute:02d}:{s:02d}", WEB, "FTP-Patator", "FTP-Patator") for s in range(n)]
    scorer = RiskScorer(ScoringConfig.default()).fit(flows(rows))
    b1, b2 = scorer.thresholds_
    assert b1 <= b2
    assert scorer.fitted_on_["n_alerts"] == 8
    assert scorer.fitted_on_["method"] == "quantile"


def test_8_alert_records_json(make_scorer, flows):
    df = flows([
        ("2017-07-06 10:40:01", WEB, SQLI, SQLI),
        ("2017-07-06 10:41:01", UNREGISTERED, "PortScan", "BENIGN"),
    ])
    records = RiskScorer.to_alert_records(make_scorer().score(df, true_col="label"))
    json.dumps(records, ensure_ascii=False)
    assert len(records) == 2
    assert all(r["rationale"].startswith("위험도") for r in records)


def test_9_validate_rejects_bad_impact_level():
    cfg = ScoringConfig.default()
    cfg.impact["levels"]["PortScan"] = 5
    with pytest.raises(ValueError):
        cfg.validate()


def test_10_min_share_filters_minor_types(make_scorer, flows):
    rows = [(f"2017-07-07 14:10:{i % 60:02d}", WEB, "PortScan", "PortScan") for i in range(99)]
    rows.append(("2017-07-07 14:10:30", WEB, "Bot", "Bot"))
    df = flows(rows)
    a = make_scorer(min_share=0.05).score(df).iloc[0]
    assert (a["I"], a["impact_type"]) == (1, "PortScan")
    b = make_scorer(min_share=0.0).score(df).iloc[0]
    assert (b["I"], b["impact_type"]) == (3, "Bot")
