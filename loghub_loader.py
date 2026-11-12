"""LogHub(OpenSSH, Apache) 샘플 로그를 rules.py 스키마로 변환하는 파서.

목적: CICIDS2017은 "정답 라벨이 있는 성능 평가용", LogHub는 "정답 라벨이
없는 룰 동작 검증용"으로 역할을 분리한다. 여기서 나오는 결과는 절대
precision/recall이 아니라 "이 룰이 실제 공개 로그에서 뭘 잡아내는가"를
보여주는 정성적 확인용이다.

데이터 출처: https://github.com/logpai/loghub (OpenSSH_2k.log, Apache_2k.log)
- OpenSSH_2k.log: 2000줄 sshd 인증 로그 샘플. GitHub 저장소에 직접 들어있어
  원본 전체(Zenodo, 수십만 줄)를 받을 필요 없이 바로 쓸 수 있다.
- Apache_2k.log: 2000줄 Apache *에러* 로그 샘플. 주의: 이건 access log가
  아니라 error log라서 HTTP 요청/쿼리스트링/상태코드가 없다. 1999줄 중
  "[client IP]"가 붙은 줄은 32줄뿐이고, 그 32줄도 전부 동일한
  "Directory index forbidden by rule: /var/www/html/" 메시지라 SQLi/XSS
  같은 payload 기반 시그니처(R-WEB-01)를 테스트할 재료가 사실상 없다.
  이 사실은 report()에서 그대로 드러낸다 - 억지로 매칭시키지 않는다.

변환된 레코드는 rules.py가 쓰는 세션 기반 스키마를 따른다. 단, SSH/Apache
서버 로그에는 세션 쿠키 개념이 없으므로 session_id = "IP_<출발지IP>"로
의사-세션을 만들어 기존 detect_brute_force/detect_web_attack을 그대로
재사용한다 (rules.py 자체는 수정하지 않음).
"""

import argparse
import re
from datetime import datetime
from pathlib import Path

from rules import detect_brute_force, detect_web_attack

# OpenSSH_2k.log에는 연도 정보가 없다 (syslog 표준 포맷이 연도를 안 남김).
# DRAFT: 임의로 2015년을 가정한다. 브루트포스 룰은 "같은 데이터셋 내 상대적
# 시간 간격"만 보므로 실제 연도가 무엇이든 탐지 결과에는 영향이 없다.
ASSUMED_OPENSSH_YEAR = 2015

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[^:\[]+)(\[\d+\])?:\s*(?P<msg>.*)$"
)
_SSH_AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted)\s+(password|publickey)\s+for\s+"
    r"(invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)
# syslogd는 짧은 시간에 완전히 동일한 메시지가 반복되면 한 줄로 축약해서
# "message repeated N times: [ <원본 메시지> ]" 형태로 남긴다. 이걸 그냥
# "auth 메시지 아님"으로 버리면 브루트포스 시도 횟수를 실제보다 적게 센다
# (실제로 이 샘플에서 2개 IP가 이 때문에 탐지에서 누락됨 - 발견 후 수정함).
_REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]$")

_APACHE_HEADER_RE = re.compile(
    r"^\[(?P<ts>\w{3} \w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\]\s+\[(?P<level>\w+)\]\s+(?P<msg>.*)$"
)
_APACHE_CLIENT_RE = re.compile(r"^\[client (?P<ip>[\d.]+)\]\s*(?P<rest>.*)$")


def parse_openssh_log(path, max_examples=5):
    """OpenSSH 샘플 로그를 rules.py 스키마(auth 이벤트)로 변환한다.

    반환: (records, stats). stats에는 정답 라벨이 없다는 점을 상기시키는
    필드는 없고, 순수 파싱 통계만 담는다.
    """
    records = []
    total = 0
    unparsed_examples = []
    unparsed_count = 0
    non_auth_count = 0  # syslog 줄로는 파싱됐지만 로그인 성공/실패 메시지가 아닌 줄
    collapsed_repeats = 0  # "message repeated N times" 축약 줄에서 복원된 이벤트 수

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            total += 1

            m = _SYSLOG_RE.match(line)
            if not m:
                unparsed_count += 1
                if len(unparsed_examples) < max_examples:
                    unparsed_examples.append(line)
                continue

            msg = m.group("msg")
            repeat_count = 1
            rep_m = _REPEATED_RE.match(msg)
            if rep_m:
                repeat_count = int(rep_m.group("count"))
                msg = rep_m.group("inner")
                collapsed_repeats += repeat_count

            auth_m = _SSH_AUTH_RE.match(msg)
            if not auth_m:
                non_auth_count += 1
                continue

            # syslog 축약 줄에는 반복된 각 메시지의 개별 타임스탬프가 없다.
            # DRAFT 근사치: 축약 줄의 타임스탬프를 repeat_count번 모두에 사용한다.
            # (실제 간격보다 조밀하게 잡힐 수 있어 브루트포스 탐지 쪽으로는
            # 보수적이지 않고 관대한 근사다 - 윈도우 안에 더 쉽게 들어감)
            ts = _parse_openssh_timestamp(m.group("ts"))
            ip = auth_m.group("ip")
            status = "success" if auth_m.group("result") == "Accepted" else "fail"
            for _ in range(repeat_count):
                records.append({
                    "timestamp": ts.isoformat(),
                    "session_id": f"IP_{ip}",
                    "src_ip": ip,
                    "event_type": "auth",
                    "status": status,
                    "dst_port": 22,
                    "raw_line": line,
                })

    stats = {
        "source": str(path),
        "total_lines": total,
        "unparsed_syslog_lines": unparsed_count,
        "unparsed_examples": unparsed_examples,
        "non_auth_lines": non_auth_count,
        "auth_event_lines": len(records),
        "collapsed_repeat_events_expanded": collapsed_repeats,
    }
    return records, stats


def _parse_openssh_timestamp(ts_text):
    # "Dec 10 06:55:46" -> datetime(ASSUMED_OPENSSH_YEAR, 12, 10, 6, 55, 46)
    dt = datetime.strptime(f"{ASSUMED_OPENSSH_YEAR} {ts_text}", "%Y %b %d %H:%M:%S")
    return dt


def parse_apache_log(path, max_examples=5):
    """Apache 에러 로그 샘플을 rules.py 스키마(http_request 이벤트)로 변환한다.

    주의: 이 데이터셋은 access log가 아니라 error log라서 HTTP 상태코드와
    쿼리스트링이 없다. path 필드에는 에러 메시지 본문을 그대로 넣고,
    status는 None(알 수 없음)으로 둔다. [client IP]가 없는 줄은 어떤
    세션(IP)에 귀속시킬 수 없으므로 변환 대상에서 제외한다.
    """
    records = []
    total = 0
    unparsed_examples = []
    unparsed_count = 0
    no_client_ip_count = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            total += 1

            m = _APACHE_HEADER_RE.match(line)
            if not m:
                unparsed_count += 1
                if len(unparsed_examples) < max_examples:
                    unparsed_examples.append(line)
                continue

            client_m = _APACHE_CLIENT_RE.match(m.group("msg"))
            if not client_m:
                no_client_ip_count += 1
                continue

            ts = datetime.strptime(m.group("ts"), "%a %b %d %H:%M:%S %Y")
            ip = client_m.group("ip")
            records.append({
                "timestamp": ts.isoformat(),
                "session_id": f"IP_{ip}",
                "src_ip": ip,
                "event_type": "http_request",
                "path": client_m.group("rest"),
                "query": "",
                "status": None,  # error log에는 HTTP 상태코드가 없음
                "dst_port": 80,
                "raw_line": line,
            })

    stats = {
        "source": str(path),
        "total_lines": total,
        "unparsed_header_lines": unparsed_count,
        "unparsed_examples": unparsed_examples,
        "no_client_ip_lines": no_client_ip_count,
        "http_request_records": len(records),
    }
    return records, stats


def _print_parse_stats(label, stats, extra_keys):
    print(f"\n[{label} 파싱 통계]")
    print(f"  총 줄 수: {stats['total_lines']}")
    for key, desc in extra_keys:
        print(f"  {desc}: {stats[key]}")
    examples = stats.get("unparsed_examples") or []
    if examples:
        print(f"  파싱 실패 예시 (최대 {len(examples)}건):")
        for ex in examples:
            print(f"    - {ex}")


def run_report(ssh_path, apache_path):
    print("=" * 70)
    print("LogHub 룰 동작 검증 리포트")
    print("정답 라벨 없음 - 아래 수치는 precision/recall이 아니라")
    print("'이 룰이 실제 공개 로그에서 무엇을 잡아내는가'를 보여주는 참고용입니다.")
    print("=" * 70)

    ssh_records, ssh_stats = parse_openssh_log(ssh_path)
    _print_parse_stats(
        "OpenSSH", ssh_stats,
        [
            ("unparsed_syslog_lines", "syslog 형식 자체가 안 맞아 건너뛴 줄"),
            ("non_auth_lines", "syslog 파싱은 됐지만 로그인 성공/실패 메시지가 아닌 줄"),
            ("auth_event_lines", "auth 이벤트로 변환된 줄 (Failed/Accepted password)"),
            ("collapsed_repeat_events_expanded", "'message repeated N times' 축약에서 복원된 이벤트 수"),
        ],
    )

    bf_hits = detect_brute_force(ssh_records)
    print(f"\n[R-BF-01 브루트포스 룰 적용 결과] 탐지된 IP(의사 세션) 수: {len(bf_hits)}")
    for hit in bf_hits[:10]:
        print(f"  - {hit['entity']} ({hit['source_ip']}): {hit['detail']}")
    if len(bf_hits) > 10:
        print(f"  ... 외 {len(bf_hits) - 10}건 더")

    apache_records, apache_stats = parse_apache_log(apache_path)
    _print_parse_stats(
        "Apache", apache_stats,
        [
            ("unparsed_header_lines", "에러로그 헤더 형식이 안 맞아 건너뛴 줄"),
            ("no_client_ip_lines", "[client IP]가 없어 세션을 특정할 수 없는 줄 (제외)"),
            ("http_request_records", "http_request 이벤트로 변환된 줄"),
        ],
    )
    print(
        "\n  한계: LogHub의 Apache_2k.log는 access log가 아니라 error log라서 "
        "HTTP 요청/쿼리스트링/상태코드가 없습니다. [client IP]가 붙은 줄도 전부 "
        "'Directory index forbidden' 메시지뿐이라 SQLi/XSS payload가 존재하지 않습니다. "
        "R-WEB-01은 이 데이터셋으로는 '신호가 있을 때 잡는지'를 검증할 수 없고, "
        "'신호가 없을 때 오탐하지 않는지'만 확인됩니다."
    )

    web_hits = detect_web_attack(apache_records)
    print(f"\n[R-WEB-01 웹공격 룰 적용 결과] 탐지 건수: {len(web_hits)} (0건 예상)")
    for hit in web_hits[:10]:
        print(f"  - {hit['entity']} ({hit['source_ip']}): {hit['detail']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogHub 샘플 로그로 룰 동작 검증")
    parser.add_argument("--ssh", default="data/loghub/OpenSSH_2k.log")
    parser.add_argument("--apache", default="data/loghub/Apache_2k.log")
    args = parser.parse_args()
    run_report(args.ssh, args.apache)
