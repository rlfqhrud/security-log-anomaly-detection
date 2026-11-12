"""데모용 샘플 보안 로그 생성.

정상 트래픽과 브루트포스 / 포트 스캔 / DoS / 웹 공격(SQL 인젝션·XSS) 4가지
공격 패턴이 섞인 로그를 생성한다.
"""

from datetime import datetime, timedelta

BASE_TIME = datetime(2026, 9, 22, 10, 0, 0)


def _ts(seconds_offset):
    return (BASE_TIME + timedelta(seconds=seconds_offset)).isoformat()


def _normal_traffic():
    """정상 사용자들의 로그인/접속/요청 로그."""
    logs = []
    normal_ips = ["192.168.0.11", "192.168.0.12", "192.168.0.13"]
    for i, ip in enumerate(normal_ips):
        logs.append({
            "timestamp": _ts(i * 5),
            "src_ip": ip,
            "event_type": "auth",
            "status": "success",
        })
        logs.append({
            "timestamp": _ts(i * 5 + 1),
            "src_ip": ip,
            "dst_ip": "10.0.0.5",
            "dst_port": 443,
            "event_type": "tcp_connect",
        })
        logs.append({
            "timestamp": _ts(i * 5 + 2),
            "src_ip": ip,
            "event_type": "http_request",
            "path": "/dashboard",
            "query": "",
            "status": 200,
        })
    return logs


def _brute_force_pattern():
    """203.0.113.10 -> /login 반복 실패."""
    logs = []
    src_ip = "203.0.113.10"
    for i in range(8):
        logs.append({
            "timestamp": _ts(100 + i * 3),
            "src_ip": src_ip,
            "event_type": "auth",
            "status": "fail",
        })
    return logs


def _port_scan_pattern():
    """203.0.113.20 -> 10.0.0.5 여러 포트 순차 접속 시도."""
    logs = []
    src_ip = "203.0.113.20"
    ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]
    for i, port in enumerate(ports):
        logs.append({
            "timestamp": _ts(200 + i * 2),
            "src_ip": src_ip,
            "dst_ip": "10.0.0.5",
            "dst_port": port,
            "event_type": "tcp_connect",
        })
    return logs


def _dos_pattern():
    """203.0.113.30 -> 짧은 시간에 대량 요청."""
    logs = []
    src_ip = "203.0.113.30"
    for i in range(25):
        logs.append({
            "timestamp": _ts(300 + i * 0.3),
            "src_ip": src_ip,
            "event_type": "http_request",
            "path": "/api/items",
            "query": "",
            "status": 200,
        })
    return logs


def _web_attack_pattern():
    """198.51.100.7 -> SQL 인젝션, 198.51.100.20 -> XSS 시도."""
    return [
        {
            "timestamp": _ts(400),
            "src_ip": "198.51.100.7",
            "event_type": "http_request",
            "path": "/login",
            "query": "user=admin' OR '1'='1&pass=x",
            "status": 401,
        },
        {
            "timestamp": _ts(402),
            "src_ip": "198.51.100.7",
            "event_type": "http_request",
            "path": "/product",
            "query": "id=1 UNION SELECT username,password FROM users",
            "status": 200,
        },
        {
            "timestamp": _ts(410),
            "src_ip": "198.51.100.20",
            "event_type": "http_request",
            "path": "/search",
            "query": "q=<script>alert(1)</script>",
            "status": 200,
        },
    ]


def load_sample_logs():
    """정상 트래픽 + 4가지 공격 패턴이 섞인 샘플 로그를 시간순으로 반환한다."""
    logs = []
    logs.extend(_normal_traffic())
    logs.extend(_brute_force_pattern())
    logs.extend(_port_scan_pattern())
    logs.extend(_dos_pattern())
    logs.extend(_web_attack_pattern())
    logs.sort(key=lambda log: log["timestamp"])
    return logs
