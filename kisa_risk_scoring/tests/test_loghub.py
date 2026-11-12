"""LogHub 변환기(템플릿 판정) 테스트."""
from kisa_scoring import loghub


def test_classify_openssh_templates():
    c = loghub.classify
    assert c("sshd", "Failed password for invalid user test from 1.2.3.4 port 5 ssh2")[:3] == ("SSH-BruteForce", "failed login", "1.2.3.4")
    assert c("sshd", "message repeated 5 times: [ Failed password for root from 1.2.3.4 port 5 ssh2]")[4] == 5
    assert c("sshd", "reverse mapping checking getaddrinfo for x.com [5.6.7.8] failed - POSSIBLE BREAK-IN ATTEMPT!")[0] == "SSH-Recon"
    assert c("sshd", "Did not receive identification string from 5.6.7.8")[0] == "SSH-Recon"
    # 같은 시도의 중복 줄은 판정하지 않는다
    assert c("sshd", "Invalid user test from 1.2.3.4")[0] == loghub.BENIGN
    assert c("sshd", "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=1.2.3.4")[0] == loghub.BENIGN


def test_classify_linux_pam_and_ftp():
    c = loghub.classify
    assert c("sshd(pam_unix)", "authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=9.9.9.9")[0] == "SSH-BruteForce"
    assert c("ftpd", "connection from 9.9.9.9 () at Sun Jul 17 2005")[:4] == ("FTP-Probe", "ftp connection", "9.9.9.9", 21)


def test_login_after_failures_and_repeat_expansion(tmp_path):
    log = tmp_path / "ssh.log"
    lines = [f"Dec 10 06:55:{i:02d} LabSZ sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2" for i in range(4)]
    lines.append("Dec 10 06:55:30 LabSZ sshd[1]: message repeated 2 times: [ Failed password for root from 1.2.3.4 port 5 ssh2]")
    lines.append("Dec 10 06:56:00 LabSZ sshd[1]: Accepted password for root from 1.2.3.4 port 5 ssh2")
    lines.append("Dec 10 06:56:01 LabSZ sshd[1]: Accepted password for bob from 7.7.7.7 port 5 ssh2")
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ev = loghub.parse_file(log, "openssh")
    types = [e["event_type"] for e in ev]
    assert types.count("SSH-BruteForce") == 6                     # 4 + 반복 2
    assert types.count("SSH-LoginAfterFailures") == 1             # 실패 6회 후 성공
    assert ev[-1]["event_type"] == loghub.BENIGN                  # 실패 이력 없는 성공은 정상
    assert ev[0]["dst_ip"] == "192.0.2.10" and ev[0]["ts"].startswith("2015-12-10")


def test_split_keeps_minute_on_one_side():
    ev = [{"ts": f"2015-12-10T06:5{m}:{s:02d}"} for m in range(3) for s in range(3)]
    calib, evald = loghub.split_by_time(ev, 0.5)
    assert len(calib) + len(evald) == len(ev)
    assert {e["ts"][:16] for e in calib}.isdisjoint({e["ts"][:16] for e in evald})
