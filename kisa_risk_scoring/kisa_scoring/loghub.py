"""LogHub(https://github.com/logpai/loghub) 실제 서버 로그 → 위험도 산정 입력(JSONL) 변환기.

LogHub 로그에는 공격 정답 레이블이 없어 LightGBM을 학습할 수 없다. 그래서 이 데이터로 검증할 때는
sshd·ftpd 메시지 템플릿(시그니처)으로 줄마다 판정하고, 그 결과를 이상탐지 단계의 출력으로 쓴다.

판정 규칙 (event_type → 충격도는 config/loghub.yaml)
    SSH-BruteForce         로그인 실패 1회 = 1건 ("Failed password/none", 구형 pam_unix "authentication failure",
                           "message repeated N times: [ Failed ...]"는 N건). 같은 시도의 중복 줄
                           (Invalid user, input_userauth_request, check pass 등)은 세지 않는다.
    SSH-LoginAfterFailures 이전에 로그인 실패가 5회 이상인 출발지에서 로그인 성공 (계정 탈취 의심)
    SSH-Recon              역방향 DNS 불일치(POSSIBLE BREAK-IN ATTEMPT), 식별 문자열 없음, 잘못된 프로토콜 버전
    FTP-Probe              ftpd "connection from" (같은 초에 수십 건씩 몰리는 접속 시도)
    BENIGN                 그 밖의 줄

목적지: LogHub는 서버 IP를 공개하지 않아 호스트명만 있다. 문서용 예약 대역(192.0.2.0/24, RFC 5737)의
IP를 호스트마다 붙이고, 자산 등급은 config/loghub.yaml의 자산표에서 준다.

실행:
    python -m kisa_scoring.loghub --openssh OpenSSH_2k.log --linux Linux_2k.log --out-dir loghub_events
    → calib.jsonl(각 로그 앞 50%), eval.jsonl(나머지 50%), all.jsonl, convert_summary.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

BENIGN = "BENIGN"
HOST_IP = {"LabSZ": "192.0.2.10", "combo": "192.0.2.20"}   # RFC 5737 문서용 대역
DEFAULT_YEAR = {"openssh": 2015, "linux": 2005}             # syslog 형식은 연도를 남기지 않는다
LOGIN_AFTER_FAILURES = 5

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
LINE_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
                     r"(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")

RULES = [
    # (event_type, 시그니처 이름, 정규식, 목적지 포트)
    ("SSH-BruteForce", "repeated failed login", re.compile(rf"message repeated (?P<n>\d+) times: \[ Failed (?:password|none) for .* from {_IP}"), 22),
    ("SSH-BruteForce", "failed login", re.compile(rf"^Failed (?:password|none) for (?:invalid user )?\S+ from {_IP}"), 22),
    ("SSH-Recon", "reverse DNS mismatch (POSSIBLE BREAK-IN ATTEMPT)", re.compile(rf"reverse mapping checking getaddrinfo for .* \[{_IP}\] failed"), 22),
    ("SSH-Recon", "no identification string (scanner)", re.compile(rf"^Did not receive identification string from {_IP}"), 22),
    ("SSH-Recon", "bad protocol version", re.compile(rf"^Bad protocol version identification .* from {_IP}"), 22),
    ("FTP-Probe", "ftp connection", re.compile(rf"^connection from {_IP}"), 21),
]
ACCEPTED_RE = re.compile(rf"^Accepted \S+ for \S+ from {_IP}")
PAM_FAIL_RE = re.compile(r"authentication failure;.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
ANY_IP_RE = re.compile(_IP)


def classify(proc: str, msg: str) -> tuple[str, str, str | None, int | None, int]:
    """(event_type, signature, src_ip, dst_port, 건수)."""
    if proc == "sshd(pam_unix)":          # 구형 로그(Linux_2k)에는 Failed password 줄이 없어 pam 실패가 시도 1회다
        m = PAM_FAIL_RE.search(msg)
        if m:
            return "SSH-BruteForce", "pam authentication failure", m.group("ip"), 22, 1
    for event_type, sig, rx, port in RULES:
        m = rx.search(msg)
        if m:
            n = int(m.groupdict().get("n") or 1)
            return event_type, sig, m.group("ip"), port, n
    m = ACCEPTED_RE.search(msg)
    if m:
        return "ACCEPTED", "accepted login", m.group("ip"), 22, 1
    m = ANY_IP_RE.search(msg)
    return BENIGN, "", m.group("ip") if m else None, None, 1


def parse_file(path: str | Path, kind: str, year: int | None = None) -> list[dict]:
    path = Path(path)
    year = year or DEFAULT_YEAR[kind]
    events, failures = [], Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, start=1):
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            host = m.group("host")
            ts = datetime.strptime(f"{year} {m.group('mon')} {m.group('day')} {m.group('time')}", "%Y %b %d %H:%M:%S")
            event_type, sig, ip, port, n = classify(m.group("proc"), m.group("msg"))
            if event_type == "ACCEPTED":
                if ip and failures[ip] >= LOGIN_AFTER_FAILURES:
                    event_type, sig = "SSH-LoginAfterFailures", f"login success after {failures[ip]} failures"
                else:
                    event_type, sig = BENIGN, ""
            if event_type == "SSH-BruteForce" and ip:
                failures[ip] += n
            base = {
                "ts": ts.isoformat(), "src_ip": ip, "dst_ip": HOST_IP.get(host, "192.0.2.99"), "host": host,
                "dst_port": port, "event_type": event_type, "signature": sig,
                "raw_ref": f"{path.name}:{lineno}", "source_log": kind,
            }
            for i in range(n):
                events.append(dict(base, raw_ref=base["raw_ref"] + (f"#{i + 1}" if n > 1 else "")))
    events.sort(key=lambda e: e["ts"])
    return events


def split_by_time(events: list[dict], ratio: float = 0.5) -> tuple[list[dict], list[dict]]:
    """앞 ratio(시간순)는 공격도 경계 보정용, 나머지는 평가용. 같은 분이 양쪽에 걸치지 않게 자른다."""
    if not events:
        return [], []
    cut = int(len(events) * ratio)
    minute = events[cut]["ts"][:16]
    while cut < len(events) and events[cut]["ts"][:16] == minute:
        cut += 1
    return events[:cut], events[cut:]


def write_jsonl(path: Path, events: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def summarize(events: list[dict]) -> dict:
    by_type = Counter(e["event_type"] for e in events)
    attackers = defaultdict(set)
    for e in events:
        if e["event_type"] != BENIGN and e["src_ip"]:
            attackers[e["host"]].add(e["src_ip"])
    return {
        "events": len(events),
        "anomalous": sum(v for k, v in by_type.items() if k != BENIGN),
        "by_type": dict(by_type.most_common()),
        "attacker_ips_by_host": {h: len(s) for h, s in attackers.items()},
        "first": events[0]["ts"] if events else None,
        "last": events[-1]["ts"] if events else None,
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    p = argparse.ArgumentParser(prog="python -m kisa_scoring.loghub", description="LogHub 로그 → 위험도 산정 입력 JSONL")
    p.add_argument("--openssh", nargs="*", default=[], help="LogHub OpenSSH 로그")
    p.add_argument("--linux", nargs="*", default=[], help="LogHub Linux 로그 (sshd pam_unix, ftpd)")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--calib-ratio", type=float, default=0.5, help="로그마다 앞부분을 보정용으로 쓰는 비율")
    args = p.parse_args(argv)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    calib, evald, everything, per_file = [], [], [], {}
    for kind, paths in (("openssh", args.openssh), ("linux", args.linux)):
        for path in paths:
            ev = parse_file(path, kind)
            c, e = split_by_time(ev, args.calib_ratio)
            calib += c
            evald += e
            everything += ev
            per_file[Path(path).name] = {**summarize(ev), "calib_events": len(c), "eval_events": len(e)}
    for name, ev in (("calib.jsonl", calib), ("eval.jsonl", evald), ("all.jsonl", everything)):
        write_jsonl(out / name, sorted(ev, key=lambda x: x["ts"]))
    summary = {"files": per_file, "calib": summarize(sorted(calib, key=lambda x: x["ts"])),
               "eval": summarize(sorted(evald, key=lambda x: x["ts"]))}
    with open(out / "convert_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    for name, s in per_file.items():
        print(f"[{name}] 이벤트 {s['events']:,}건, 이상 {s['anomalous']:,}건 {s['by_type']}  ({s['first']} ~ {s['last']})")
    print(f"보정 {len(calib):,}건 / 평가 {len(evald):,}건 → {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
