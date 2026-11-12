"""가짜 웹사이트(target_site.py)에서 생성한 로그를 보관하는 공유 저장소.

target_site.py가 로그인 / 검색 / 접속 이벤트를 append_log()로 기록하면,
main.py의 /api/scan이 load_logs()로 읽어 샘플 로그와 합쳐 분석한다.
파일(shared_logs.json) 하나를 두 서버 프로세스가 공유하는 가장 단순한 방식이다.
"""

import json
from pathlib import Path
from threading import Lock

LOG_FILE = Path(__file__).resolve().parent / "shared_logs.json"
_lock = Lock()


def append_log(entry):
    with _lock:
        logs = _read()
        logs.append(entry)
        _write(logs)


def load_logs():
    with _lock:
        return _read()


def clear_logs():
    with _lock:
        _write([])


def _read():
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _write(logs):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)
