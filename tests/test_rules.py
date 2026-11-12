"""rules.py 단위 테스트: 브루트포스/포트스캔/DoS(Flood·Slow)/웹공격."""

from datetime import datetime, timedelta

from rules import (
    detect_brute_force,
    detect_dos_flood,
    detect_dos_slow,
    detect_port_scan,
    detect_web_attack,
    run_all_rules,
)

BASE = datetime(2026, 1, 1, 0, 0, 0)


def _ts(offset_seconds):
    return (BASE + timedelta(seconds=offset_seconds)).isoformat()


def _auth(session_id, offset, status, ip="203.0.113.1"):
    return {"timestamp": _ts(offset), "session_id": session_id, "src_ip": ip,
            "event_type": "auth", "status": status}


def _visit(session_id, offset, ip="203.0.113.1", path="/home", query=""):
    return {"timestamp": _ts(offset), "session_id": session_id, "src_ip": ip,
            "event_type": "http_request", "path": path, "query": query, "status": 200}


def _connect(session_id, offset, port, ip="203.0.113.1"):
    return {"timestamp": _ts(offset), "session_id": session_id, "src_ip": ip,
            "event_type": "tcp_connect", "dst_port": port}


def test_brute_force_triggers_at_five_fails_within_window():
    logs = [_auth("S1", i * 5, "fail") for i in range(5)]  # 0,5,10,15,20초
    hits = detect_brute_force(logs)
    assert len(hits) == 1
    assert hits[0]["entity"] == "S1"
    assert "5회" in hits[0]["detail"]


def test_brute_force_does_not_trigger_below_threshold():
    logs = [_auth("S1", i * 5, "fail") for i in range(4)]
    assert detect_brute_force(logs) == []


def test_brute_force_ignores_successful_logins():
    logs = [_auth("S1", i * 5, "success") for i in range(10)]
    assert detect_brute_force(logs) == []


def test_port_scan_triggers_on_six_distinct_ports():
    logs = [_connect("S1", i * 5, port) for i, port in enumerate([21, 22, 23, 80, 443, 3389])]
    hits = detect_port_scan(logs)
    assert len(hits) == 1
    assert "6개" in hits[0]["detail"]


def test_port_scan_ignores_repeated_connections_to_same_port():
    logs = [_connect("S1", i * 5, 80) for i in range(10)]
    assert detect_port_scan(logs) == []


def test_dos_flood_triggers_on_burst():
    logs = [_visit("S1", i * 0.3) for i in range(20)]  # 20건을 ~6초 안에
    hits = detect_dos_flood(logs)
    assert len(hits) == 1
    assert hits[0]["attack_type"] == "DoS 공격(Flood)"


def test_dos_slow_triggers_on_sustained_low_rate_without_burst():
    # 120초 동안 15건, 8초 간격으로 퍼져 있어 flood 임계값(20건/10초)은 절대 못 채움
    logs = [_visit("S1", i * 8) for i in range(15)]
    assert detect_dos_flood(logs) == []
    hits = detect_dos_slow(logs)
    assert len(hits) == 1
    assert hits[0]["attack_type"] == "DoS 공격(Slow)"


def test_dos_slow_respects_exclude_entities():
    logs = [_visit("S1", i * 8) for i in range(15)]
    hits = detect_dos_slow(logs, exclude_entities={"S1"})
    assert hits == []


def test_run_all_rules_does_not_double_count_flood_session_as_slow():
    # flood 패턴(짧고 굵게)은 당연히 "120초 안에 15건 이상"도 만족하므로,
    # exclude 처리 없이 그대로 두면 Flood + Slow 둘 다 찍혀서 점수가 중복된다.
    logs = [_visit("S1", i * 0.3) for i in range(20)]
    hits = run_all_rules(logs)
    attack_types = [h["attack_type"] for h in hits if h["entity"] == "S1"]
    assert attack_types.count("DoS 공격(Flood)") == 1
    assert "DoS 공격(Slow)" not in attack_types


def test_web_attack_detects_sqli_xss_and_path_traversal():
    logs = [
        _visit("S1", 0, path="/login", query="user=admin' OR '1'='1"),
        _visit("S2", 1, path="/search", query="q=<script>alert(1)</script>"),
        _visit("S3", 2, path="/files", query="path=../../etc/passwd"),
    ]
    hits = detect_web_attack(logs)
    types = {h["entity"]: h["attack_type"] for h in hits}
    assert types["S1"] == "웹 공격(SQL 인젝션)"
    assert types["S2"] == "웹 공격(XSS)"
    assert types["S3"] == "웹 공격(경로 탐색)"


def test_web_attack_ignores_benign_queries():
    logs = [_visit("S1", 0, path="/search", query="q=노트북")]
    assert detect_web_attack(logs) == []


def test_empty_logs_produce_no_hits():
    assert run_all_rules([]) == []
