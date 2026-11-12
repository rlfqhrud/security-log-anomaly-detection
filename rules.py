"""보안 로그 이상탐지 룰 엔진.

브루트포스 / 포트 스캔 / DoS / 웹 공격(SQL 인젝션·XSS 등) 4가지 룰을 로그에 대해
실행하고, 공통 형식의 hit(위반 이벤트) 리스트를 반환한다.

탐지·집계의 기준 단위는 실명/이메일 등 개인 식별 정보가 아니라 세션 단위
임시 식별자(session_id)다. 출발지 IP(source_ip)는 담당자가 조사할 때 참고할
수 있도록 hit에 함께 남기되, 그룹핑 키로는 쓰지 않는다.
"""

from collections import defaultdict
from datetime import datetime


def _parse_ts(ts):
    return datetime.fromisoformat(ts)


def detect_brute_force(logs, fail_threshold=5, window_seconds=60):
    """짧은 시간 안에 로그인 실패가 반복되는 세션을 탐지한다."""
    attempts = defaultdict(list)
    for log in logs:
        if log.get("event_type") == "auth" and log.get("status") == "fail":
            attempts[log["session_id"]].append((_parse_ts(log["timestamp"]), log.get("src_ip")))

    hits = []
    for session_id, records in attempts.items():
        records.sort(key=lambda r: r[0])
        window = []
        for ts, ip in records:
            window.append((ts, ip))
            window = [w for w in window if (ts - w[0]).total_seconds() <= window_seconds]
            if len(window) >= fail_threshold:
                hits.append({
                    "rule": "brute_force",
                    "attack_type": "브루트포스 공격",
                    "entity": session_id,
                    "source_ip": ip,
                    "score": 0.25,
                    "detail": f"{window_seconds}초 이내 로그인 실패 {len(window)}회",
                })
                break
    return hits


def detect_port_scan(logs, port_threshold=6, window_seconds=60):
    """짧은 시간 안에 여러 포트에 접속을 시도하는 세션을 탐지한다."""
    connections = defaultdict(list)
    for log in logs:
        if log.get("event_type") == "tcp_connect":
            connections[log["session_id"]].append(
                (_parse_ts(log["timestamp"]), log.get("src_ip"), log.get("dst_port"))
            )

    hits = []
    for session_id, records in connections.items():
        records.sort(key=lambda r: r[0])
        window = []
        for ts, ip, port in records:
            window.append((ts, ip, port))
            window = [w for w in window if (ts - w[0]).total_seconds() <= window_seconds]
            distinct_ports = {w[2] for w in window}
            if len(distinct_ports) >= port_threshold:
                hits.append({
                    "rule": "port_scan",
                    "attack_type": "포트 스캔 공격",
                    "entity": session_id,
                    "source_ip": ip,
                    "score": 0.4,
                    "detail": f"{window_seconds}초 이내 서로 다른 포트 {len(distinct_ports)}개 접근",
                })
                break
    return hits


def _requests_by_session(logs):
    requests_by_session = defaultdict(list)
    for log in logs:
        if log.get("event_type") == "http_request":
            requests_by_session[log["session_id"]].append(
                (_parse_ts(log["timestamp"]), log.get("src_ip"))
            )
    return requests_by_session


def detect_dos_flood(logs, request_threshold=20, window_seconds=10):
    """짧은 시간 안에 비정상적으로 많은 요청을 보내는 세션을 탐지한다
    ("짧고 굵게" - Hulk/GoldenEye류 폭주형 DoS의 근사치).

    세션 기반 라이브 데모용 근사 구현이다. CICIDS2017 플로우 통계 기반
    R-DOS-FLOOD(flow_rules.py, Destination Port + Flow Packets/s 기준)와는
    입력 신호 자체가 다른 별개 구현이며, 서로의 검증 결과를 대신하지 않는다.
    """
    hits = []
    for session_id, records in _requests_by_session(logs).items():
        records.sort(key=lambda r: r[0])
        window = []
        for ts, ip in records:
            window.append((ts, ip))
            window = [w for w in window if (ts - w[0]).total_seconds() <= window_seconds]
            if len(window) >= request_threshold:
                hits.append({
                    "rule": "dos_flood",
                    "attack_type": "DoS 공격(Flood)",
                    "entity": session_id,
                    "source_ip": ip,
                    "score": 0.55,
                    "detail": f"{window_seconds}초 이내 요청 {len(window)}건",
                })
                break
    return hits


def detect_dos_slow(logs, request_threshold=15, window_seconds=120, exclude_entities=None):
    """오랜 시간에 걸쳐 느리지만 꾸준히 요청을 보내는 세션을 탐지한다
    ("길고 가늘게" - slowloris/Slowhttptest류 저속 DoS의 근사치).

    detect_dos_flood와 같은 입력(세션별 http_request 타임스탬프)을 쓰지만
    윈도우가 더 길고 임계값은 더 낮다. exclude_entities에 담긴 세션은
    건너뛴다 - run_all_rules()가 이미 Flood로 잡힌 세션을 Slow로 또 잡아
    점수가 이중으로 쌓이는 걸 막으려고 넘겨준다.

    CICIDS2017 플로우 통계 기반 R-DOS-SLOW(flow_rules.py, Flow Duration +
    Flow Packets/s 기준)와는 입력 신호가 다른 별개 근사 구현이다.
    """
    exclude_entities = exclude_entities or set()
    hits = []
    for session_id, records in _requests_by_session(logs).items():
        if session_id in exclude_entities:
            continue
        records.sort(key=lambda r: r[0])
        window = []
        for ts, ip in records:
            window.append((ts, ip))
            window = [w for w in window if (ts - w[0]).total_seconds() <= window_seconds]
            if len(window) >= request_threshold:
                hits.append({
                    "rule": "dos_slow",
                    "attack_type": "DoS 공격(Slow)",
                    "entity": session_id,
                    "source_ip": ip,
                    "score": 0.55,
                    "detail": f"{window_seconds}초 동안 느리지만 꾸준한 요청 {len(window)}건",
                })
                break
    return hits


_SQLI_PATTERNS = ["' or ", "union select", "1=1", "' or '1'='1", "drop table"]
_XSS_PATTERNS = ["<script", "onerror=", "javascript:"]
_PATH_TRAVERSAL_PATTERNS = ["../../", "..\\..\\", "/etc/passwd"]


def detect_web_attack(logs):
    """HTTP 요청 경로/쿼리에서 SQL 인젝션, XSS, 경로 탐색 패턴을 탐지한다."""
    hits = []
    for log in logs:
        if log.get("event_type") != "http_request":
            continue
        target = f"{log.get('path', '')} {log.get('query', '')}".lower()
        session_id = log.get("session_id")
        ip = log.get("src_ip")

        if any(p in target for p in _SQLI_PATTERNS):
            hits.append({
                "rule": "web_attack",
                "attack_type": "웹 공격(SQL 인젝션)",
                "entity": session_id,
                "source_ip": ip,
                "score": 0.6,
                "detail": f"SQL 인젝션 의심 요청: {log.get('path', '')}?{log.get('query', '')}",
            })
        elif any(p in target for p in _XSS_PATTERNS):
            hits.append({
                "rule": "web_attack",
                "attack_type": "웹 공격(XSS)",
                "entity": session_id,
                "source_ip": ip,
                "score": 0.45,
                "detail": f"XSS 의심 요청: {log.get('path', '')}?{log.get('query', '')}",
            })
        elif any(p in target for p in _PATH_TRAVERSAL_PATTERNS):
            hits.append({
                "rule": "web_attack",
                "attack_type": "웹 공격(경로 탐색)",
                "entity": session_id,
                "source_ip": ip,
                "score": 0.5,
                "detail": f"경로 탐색 의심 요청: {log.get('path', '')}?{log.get('query', '')}",
            })
    return hits


def run_all_rules(logs):
    """모든 룰을 실행하고 hit 리스트를 합쳐서 반환한다."""
    hits = []
    hits.extend(detect_brute_force(logs))
    hits.extend(detect_port_scan(logs))

    flood_hits = detect_dos_flood(logs)
    hits.extend(flood_hits)
    # 이미 Flood로 잡힌 세션은 Slow 룰에서 제외 (burst는 당연히 "긴 윈도우 안의
    # 느린 누적" 조건도 만족하므로, 빼지 않으면 같은 공격이 두 번 점수에 반영됨).
    flood_entities = {h["entity"] for h in flood_hits}
    hits.extend(detect_dos_slow(logs, exclude_entities=flood_entities))

    hits.extend(detect_web_attack(logs))
    return hits
