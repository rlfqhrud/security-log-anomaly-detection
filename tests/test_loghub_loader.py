"""loghub_loader.py 파서 단위 테스트: 정상 줄 / 깨진 줄 / 빈 파일."""

from pathlib import Path

from loghub_loader import parse_apache_log, parse_openssh_log

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_openssh_parses_valid_lines():
    records, stats = parse_openssh_log(FIXTURES / "openssh_sample.log")

    assert stats["total_lines"] == 4
    assert stats["unparsed_syslog_lines"] == 0
    assert stats["non_auth_lines"] == 1  # pam_unix 줄
    assert stats["auth_event_lines"] == 3

    fails = [r for r in records if r["status"] == "fail"]
    successes = [r for r in records if r["status"] == "success"]
    assert len(fails) == 2
    assert len(successes) == 1
    assert all(r["event_type"] == "auth" and r["dst_port"] == 22 for r in records)
    assert fails[0]["src_ip"] == "173.234.31.186"
    assert fails[0]["session_id"] == "IP_173.234.31.186"


def test_openssh_skips_unparseable_lines_without_crashing():
    records, stats = parse_openssh_log(FIXTURES / "openssh_sample_broken.log")

    assert stats["total_lines"] == 3
    assert stats["unparsed_syslog_lines"] == 2
    assert len(stats["unparsed_examples"]) == 2
    assert stats["auth_event_lines"] == 1
    assert len(records) == 1


def test_openssh_expands_message_repeated_lines(tmp_path):
    log_file = tmp_path / "repeated.log"
    log_file.write_text(
        "Dec 10 06:55:48 LabSZ sshd[24200]: "
        "message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]\n",
        encoding="utf-8",
    )

    records, stats = parse_openssh_log(log_file)

    assert stats["collapsed_repeat_events_expanded"] == 5
    assert stats["auth_event_lines"] == 5
    assert all(r["status"] == "fail" and r["src_ip"] == "5.36.59.76" for r in records)


def test_openssh_empty_file(tmp_path):
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    records, stats = parse_openssh_log(empty_file)

    assert records == []
    assert stats["total_lines"] == 0
    assert stats["auth_event_lines"] == 0


def test_apache_parses_valid_lines():
    records, stats = parse_apache_log(FIXTURES / "apache_sample.log")

    assert stats["total_lines"] == 2
    assert stats["unparsed_header_lines"] == 0
    assert stats["no_client_ip_lines"] == 1  # notice 줄 (client IP 없음)
    assert stats["http_request_records"] == 1

    assert len(records) == 1
    record = records[0]
    assert record["event_type"] == "http_request"
    assert record["src_ip"] == "222.166.160.184"
    assert record["session_id"] == "IP_222.166.160.184"
    assert record["dst_port"] == 80
    assert record["status"] is None  # error log에는 HTTP 상태코드가 없음


def test_apache_skips_unparseable_lines_without_crashing():
    records, stats = parse_apache_log(FIXTURES / "apache_sample_broken.log")

    assert stats["total_lines"] == 2
    assert stats["unparsed_header_lines"] == 1
    assert len(stats["unparsed_examples"]) == 1
    assert stats["http_request_records"] == 1


def test_apache_empty_file(tmp_path):
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    records, stats = parse_apache_log(empty_file)

    assert records == []
    assert stats["total_lines"] == 0
    assert stats["http_request_records"] == 0
