"""보안 로그 이상탐지 데모용 FastAPI 서버."""

from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

import block_store
import log_store
import risk_config
from rules import run_all_rules
from scoring import HIGH_RISK, RiskScorer

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="보안 로그 이상탐지 데모")

DEFAULT_RESPONSE_STATUS = "탐지됨"
RESPONSE_LABELS = {
    "ip_block": "IP 차단 완료",
    "account_lock": "계정 잠금 완료",
}


class RespondRequest(BaseModel):
    entity: str
    action: Literal["ip_block", "account_lock"]


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/api/scan")
def scan():
    logs = log_store.load_logs()
    hits = run_all_rules(logs)

    scorer = RiskScorer()
    scorer.add_hits(hits)
    results = scorer.results()

    for r in results:
        if r["level"] == HIGH_RISK:
            state = block_store.get_status(r["entity"])
            r["response_status"] = state["status"] if state else DEFAULT_RESPONSE_STATUS
            r["responded_at"] = state["responded_at"] if state else None

    incidents = [r for r in results if r["level"] == HIGH_RISK]

    return {
        "results": results,
        "incidents": incidents,
    }


@app.post("/api/respond")
def respond(payload: RespondRequest):
    """고위험 인시던트에 대한 대응. target_site.py가 이 상태를 읽어 실제로
    해당 entity의 요청을 거부한다 (실제 방화벽/IAM 연동은 아님)."""
    responded_at = datetime.now().isoformat()
    status = RESPONSE_LABELS[payload.action]
    block_store.set_status(payload.entity, payload.action, status, responded_at)
    return {"entity": payload.entity, "status": status, "responded_at": responded_at}


@app.get("/api/risk-levels")
def get_risk_levels():
    """등급별 임계값/참고 라벨(CVSS·KISA 매핑, 의미)을 대시보드 툴팁용으로 제공한다.
    참고용 매핑일 뿐 Risk Score와 동일 척도가 아니라는 점은 risk_levels.yaml 참고."""
    return {
        "medium_threshold": risk_config.MEDIUM_THRESHOLD,
        "high_threshold": risk_config.HIGH_THRESHOLD,
        "levels": risk_config.all_level_meta(),
    }


@app.get("/api/logs")
def get_logs():
    """정상/저위험 로그를 포함한 전체 원본 로그 이력 (알림용이 아닌 조회용).
    session_id/출발지 IP/이벤트 정보만 담고 있으며 실명·이메일 등은 없다."""
    logs = log_store.load_logs()
    return {"logs": list(reversed(logs))}


@app.post("/api/reset-live-logs")
def reset_live_logs():
    """target_site.py에서 쌓인 실시간 로그와 차단/대응 상태를 모두 초기화한다."""
    log_store.clear_logs()
    block_store.clear()
    return {"ok": True}
