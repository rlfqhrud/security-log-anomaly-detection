"""데모용 가짜 웹사이트.

로그인 / 검색 / 접속 / 포트 접속 같은 기본적인 기능만 제공하며, 각 동작을
로그로 남겨 공유 저장소(log_store)에 기록한다. 실명·이메일 등 개인 식별
정보는 전혀 수집하지 않고, 방문자를 구분하기 위한 임시 세션 식별자
(session_id)만 쿠키로 발급해 로그에 남긴다. 보안 대시보드(main.py)는 이
session_id를 기준으로 이상행위를 탐지·집계한다.

대시보드에서 "IP 차단(모의)" / "계정 잠금(모의)"을 누르면 그 상태가
block_store를 통해 여기로 전달되어 해당 세션의 요청이 실제로 거부된다.
(실제 방화벽/IAM 연동이 아니라 데모용 상태 공유일 뿐이다.)
"""

import secrets
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse

import block_store
import log_store

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="가짜 웹사이트 (데모용)")

VALID_USERNAME = "admin"
VALID_PASSWORD = "admin1234"

SESSION_COOKIE = "session_id"


def _new_session_id():
    return f"SESSION_{secrets.token_hex(4).upper()}"


def _get_session_id(request: Request, response: Response):
    """쿠키에 세션 식별자가 있으면 재사용하고, 없으면 새로 발급한다.
    실명/이메일 등은 전혀 다루지 않으며, 동일 세션의 이벤트를 묶기 위한
    임시 식별자일 뿐이다."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        session_id = _new_session_id()
        response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="lax")
    return session_id


def _client_ip(request: Request):
    return request.client.host if request.client else "unknown"


def _log(session_id, src_ip, event_type, **fields):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "src_ip": src_ip,
        "event_type": event_type,
    }
    entry.update(fields)
    log_store.append_log(entry)
    return entry


def _enforce_not_blocked(session_id, is_login=False):
    """차단/잠금된 세션이면 요청을 거부한다. IP 차단은 해당 세션의 모든 요청을,
    계정 잠금은 로그인 요청만 막는다 (계정 잠금은 인증 차단이지 네트워크 차단이 아니므로)."""
    state = block_store.get_status(session_id)
    if not state:
        return
    if state["action"] == "ip_block":
        raise HTTPException(status_code=403, detail="🚫 이 세션은 차단되어 요청이 거부되었습니다.")
    if is_login and state["action"] == "account_lock":
        raise HTTPException(status_code=423, detail="🔒 계정이 잠겨 로그인할 수 없습니다.")


@app.get("/")
def index(request: Request):
    response = FileResponse(BASE_DIR / "templates" / "target_index.html")
    _get_session_id(request, response)
    return response


@app.post("/visit")
def visit(request: Request, response: Response, path: str = Form("/home")):
    """페이지 접속(방문) 로그."""
    session_id = _get_session_id(request, response)
    ip = _client_ip(request)
    _enforce_not_blocked(session_id)
    _log(session_id, ip, "http_request", path=path, query="", status=200)
    return {"ok": True}


@app.post("/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    session_id = _get_session_id(request, response)
    ip = _client_ip(request)
    _enforce_not_blocked(session_id, is_login=True)
    success = username == VALID_USERNAME and password == VALID_PASSWORD
    _log(session_id, ip, "auth", status="success" if success else "fail")
    return {"success": success}


@app.post("/search")
def search(request: Request, response: Response, q: str = Form(...)):
    session_id = _get_session_id(request, response)
    ip = _client_ip(request)
    _enforce_not_blocked(session_id)
    _log(session_id, ip, "http_request", path="/search", query=f"q={q}", status=200)
    return {"ok": True}


@app.post("/connect")
def connect(request: Request, response: Response, dst_port: int = Form(...)):
    """포트 접속 시도 로그 (포트 스캔 탐지 시연용)."""
    session_id = _get_session_id(request, response)
    ip = _client_ip(request)
    _enforce_not_blocked(session_id)
    _log(session_id, ip, "tcp_connect", dst_port=dst_port)
    return {"ok": True}


@app.get("/api/my-status")
def my_status(request: Request, response: Response):
    """현재 세션이 차단/잠금 상태인지 알려준다 (데모 사이트 상단 배너용)."""
    session_id = _get_session_id(request, response)
    ip = _client_ip(request)
    state = block_store.get_status(session_id)
    return {"session_id": session_id, "ip": ip, "blocked": bool(state), "state": state}


@app.get("/api/log-count")
def log_count():
    return {"count": len(log_store.load_logs())}


@app.post("/api/reset-logs")
def reset_logs():
    log_store.clear_logs()
    block_store.clear()
    return {"ok": True}
