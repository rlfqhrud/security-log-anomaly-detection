"""LLM 요약 단계: 경보 레코드(위험도 점수 + 근거 문장)를 OpenAI GPT로 한국어 요약문으로 만든다.

- 입력: RiskScorer.to_alert_records()가 만든 레코드 1건 (alerts.json의 원소)
- 심각 등급은 상세 요약(추가 조사 항목 포함), 경계 등급은 짧은 요약
- 점수 근거(rationale)를 그대로 넣어 LLM이 우선순위 이유를 지어내지 않게 한다
- OPENAI_API_KEY가 없거나 호출이 실패하면 템플릿 요약으로 대체한다(시연이 멈추지 않게)

환경 변수:
    OPENAI_API_KEY   OpenAI API 키
    OPENAI_MODEL     사용할 모델 (기본 DEFAULT_MODEL)
"""
from __future__ import annotations

import json
import os
import sys
import time

DEFAULT_MODEL = "gpt-5.4-mini"
REASONING_PREFIXES = ("gpt-5", "o1", "o3", "o4")

# LLM에 넘길 필드. 나머지(raw_refs 등)는 요약에 필요 없어 토큰만 늘린다.
PROMPT_FIELDS = [
    "grade", "risk", "rationale", "T", "I", "A", "window_start", "last_seen", "timezone",
    "dst_ip", "asset_name", "flow_count", "impact_type", "attack_types", "src_ips",
]

SYSTEM_PROMPT = """당신은 보안관제센터(SOC) 분석가를 돕는 보조 도구입니다.
입력은 KISA 위험도 모델(위험도 = 공격도 T × 충격도 I × 자산가치 A)로 점수가 매겨진 경보 1건의 JSON입니다.

규칙:
- 한국어로, 담당자가 메신저 알림으로 바로 읽을 수 있게 씁니다.
- 입력 JSON에 있는 사실만 씁니다. IP, 건수, 시각, 유형을 추측하거나 바꾸지 않습니다.
- 위험도 근거는 rationale 문장의 T·I·A 값을 그대로 인용합니다.
- 권장 조치는 공격 유형에 맞는 일반적인 1차 대응만 제시하고, 확정되지 않은 피해를 단정하지 않습니다.
"""

FORMAT_SHORT = """다음 형식으로 5줄 이내로 쓰세요.
상황: (언제, 어느 자산에, 어떤 공격이 몇 건)
위험도 근거: (T, I, A 값과 의미)
권장 조치: (1~2개)"""

FORMAT_DETAILED = """다음 형식으로 10줄 이내로 쓰세요.
상황: (언제, 어느 자산에, 어떤 공격이 몇 건, 출발지)
위험도 근거: (T, I, A 값과 각각의 의미)
예상 영향: (공격 유형이 성공했을 때 침해되는 보안 속성)
권장 조치: (즉시 할 일 2~3개)
추가 조사: (확인할 로그나 지표 1~2개)"""

# 템플릿 요약용 1차 대응 (유형 이름에 포함된 키워드 → 조치)
_ACTIONS = [
    ("heartbleed", "OpenSSL 버전 확인·패치, 서버 인증서와 세션 키 교체"),
    ("infiltration", "해당 호스트 네트워크 격리, 프로세스·외부 연결 점검"),
    ("bot", "감염 의심 호스트 격리, C2 의심 목적지 차단"),
    ("sql injection", "웹 방화벽 SQL 인젝션 룰 적용, 해당 요청의 DB 쿼리 로그 확인"),
    ("xss", "입력값 검증·출력 인코딩 점검, 웹 방화벽 XSS 룰 적용"),
    ("brute force", "출발지 IP 차단, 계정 잠금 정책 적용"),
    ("patator", "출발지 IP 차단, 계정 잠금·다중 인증 적용"),
    ("ddos", "상위 회선·CDN에 트래픽 차단 요청, 출발지 대역 차단"),
    ("dos", "출발지 IP 차단, 웹 서버 연결 수·타임아웃 제한"),
    ("portscan", "출발지 IP 차단, 열린 포트 목록 점검"),
]


def _join(v) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return str(v).replace(";", ", ") if v else "-"


def recommended_action(record: dict) -> str:
    text = f"{record.get('impact_type') or ''} {record.get('attack_types') or ''}".lower()
    for key, action in _ACTIONS:
        if key in text:
            return action
    return "출발지 확인 후 차단 여부 판단, 대상 자산 로그 점검"


def build_messages(record: dict, detailed: bool) -> list[dict]:
    payload = {k: record.get(k) for k in PROMPT_FIELDS if record.get(k) is not None}
    user = (
        f"{FORMAT_DETAILED if detailed else FORMAT_SHORT}\n\n"
        f"경보 JSON:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
    )
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]


def template_summary(record: dict, detailed: bool = False) -> str:
    """LLM 없이 만드는 요약. 입력 필드만 조합하므로 사실과 어긋날 일이 없다."""
    when = record.get("window_start") or "-"
    tz = f" ({record['timezone']})" if record.get("timezone") else ""
    lines = [
        f"상황: {when}{tz}, {record.get('asset_name') or '-'}({record.get('dst_ip')})에 "
        f"{_join(record.get('impact_type') or record.get('attack_types'))} 의심 flow {record.get('flow_count')}건",
        f"위험도 근거: {record.get('rationale')}",
        f"권장 조치: {recommended_action(record)}",
    ]
    if detailed:
        lines.insert(1, f"출발지: {_join(record.get('src_ips'))}")
        lines.append("추가 조사: 같은 출발지의 다른 자산 접근 기록, 대상 서버의 인증·웹 로그")
    return "\n".join(lines)


class Summarizer:
    """OpenAI GPT 요약기. client를 주입하면(테스트·다른 호환 서버) 그것을 쓴다."""

    def __init__(self, client=None, model: str | None = None, use_llm: bool = True, max_tokens: int = 500):
        self.model = model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens
        self.stats: list[dict] = []   # 호출별 응답 시간·토큰 (결과 보고용)
        self.client = client
        if self.client is None and use_llm and os.environ.get("OPENAI_API_KEY"):
            try:
                from openai import OpenAI

                self.client = OpenAI()
            except ImportError:
                print("[경고] openai 패키지가 없어 템플릿 요약을 씁니다 (pip install openai).", file=sys.stderr)
        if not use_llm:
            self.client = None

    @property
    def uses_llm(self) -> bool:
        return self.client is not None

    def summarize(self, record: dict, detailed: bool = False) -> tuple[str, str]:
        """(요약문, 생성 방식)을 돌려준다. 방식은 모델 이름 또는 'template'."""
        if self.client is None:
            return template_summary(record, detailed), "template"
        try:
            kwargs = {"model": self.model, "messages": build_messages(record, detailed)}
            if self.model.startswith(REASONING_PREFIXES):
                # 추론 모델은 temperature를 받지 않고, 추론 토큰도 출력 한도에 포함된다
                kwargs.update(reasoning_effort="low", max_completion_tokens=self.max_tokens + 2000)
            else:
                kwargs.update(temperature=0.2, max_completion_tokens=self.max_tokens)
            t0 = time.perf_counter()
            resp = self.client.chat.completions.create(**kwargs)
            self.stats.append({
                "seconds": round(time.perf_counter() - t0, 3),
                "prompt_tokens": getattr(getattr(resp, "usage", None), "prompt_tokens", None),
                "completion_tokens": getattr(getattr(resp, "usage", None), "completion_tokens", None),
            })
            text = (resp.choices[0].message.content or "").strip()
            if text:
                return text, self.model
            print("[경고] LLM 응답이 비어 템플릿 요약으로 대체합니다.", file=sys.stderr)
        except Exception as e:  # 네트워크·인증·요금 한도 등 어떤 오류든 알림은 계속 보낸다
            print(f"[경고] LLM 호출 실패({type(e).__name__}: {e}). 템플릿 요약으로 대체합니다.", file=sys.stderr)
        return template_summary(record, detailed), "template"
