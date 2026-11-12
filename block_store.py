"""IP 차단 / 계정 잠금 상태를 두 서버 프로세스가 공유하는 저장소.

main.py의 POST /api/respond가 기록하면, target_site.py가 이를 읽어 실제로
로그인/검색/접속 요청을 거부하는 데 사용한다. 실제 방화벽·IAM과 연동하는
것이 아니라 JSON 파일 하나를 공유하는 데모용 상태 저장소다.
"""

import json
from pathlib import Path
from threading import Lock

STORE_FILE = Path(__file__).resolve().parent / "blocked_entities.json"
_lock = Lock()


def set_status(entity, action, status_label, responded_at):
    with _lock:
        data = _read()
        data[entity] = {
            "action": action,
            "status": status_label,
            "responded_at": responded_at,
        }
        _write(data)


def get_status(entity):
    with _lock:
        return _read().get(entity)


def clear():
    with _lock:
        _write({})


def _read():
    if not STORE_FILE.exists():
        return {}
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _write(data):
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
