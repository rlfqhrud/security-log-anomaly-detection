"""위험 등급 임계값/참고 라벨을 risk_levels.yaml에서 읽어오는 설정 모듈.

하드코딩 대신 외부 설정 파일로 분리해서, 추후 "룰 관리 화면"에서 코드
재배포 없이 임계값을 조정할 수 있는 구조로 만든다.

reference(CVSS/KISA 경보단계)는 담당자가 감을 잡기 위한 참고용 매핑일 뿐,
우리 Risk Score(0~1 가중합, 자체 산출 방식)와 동일한 척도가 아니다. 같은
숫자처럼 보여도 등치시키면 안 된다는 점을 UI에서도 그대로 알린다.
"""

from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).resolve().parent / "risk_levels.yaml"

LOW_RISK = "저위험"
MEDIUM_RISK = "중위험"
HIGH_RISK = "고위험"

_LABEL_TO_KEY = {LOW_RISK: "low", MEDIUM_RISK: "medium", HIGH_RISK: "high"}


def _default_config():
    """risk_levels.yaml이 없을 때 쓰는 폴백. DRAFT 원 설계값과 동일하다."""
    return {
        "levels": {
            "low": {
                "max_score": 0.3, "label": LOW_RISK,
                "reference": {"cvss": "Low (0.1-3.9)", "kisa_alert": "정상·관심"},
                "meaning": "기록·모니터링",
            },
            "medium": {
                "max_score": 0.5, "label": MEDIUM_RISK,
                "reference": {"cvss": "Medium (4.0-6.9)", "kisa_alert": "주의"},
                "meaning": "담당자 확인, 알림 발송",
            },
            "high": {
                "max_score": None, "label": HIGH_RISK,
                "reference": {"cvss": "High·Critical (7.0-10.0)", "kisa_alert": "경계·심각"},
                "meaning": "인시던트 승격, 즉시 대응·승인",
            },
        }
    }


def load_config(path=CONFIG_PATH):
    path = Path(path)
    if not path.exists():
        return _default_config()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if data else _default_config()


def build_thresholds(config):
    levels = config["levels"]
    return levels["low"]["max_score"], levels["medium"]["max_score"]


_config = load_config()
_levels = _config["levels"]
MEDIUM_THRESHOLD, HIGH_THRESHOLD = build_thresholds(_config)


def classify(score, medium_threshold=None, high_threshold=None):
    """score -> 등급 라벨. 임계값을 생략하면 현재 설정값을 쓴다.
    compare_risk_thresholds.py처럼 '이 임계값이면 어떻게 될까'를 미리
    계산해볼 때는 medium_threshold/high_threshold를 직접 넘기면 된다."""
    medium_threshold = MEDIUM_THRESHOLD if medium_threshold is None else medium_threshold
    high_threshold = HIGH_THRESHOLD if high_threshold is None else high_threshold
    if score >= high_threshold:
        return HIGH_RISK
    if score >= medium_threshold:
        return MEDIUM_RISK
    return LOW_RISK


def level_meta(label):
    """대시보드 툴팁용: 등급 라벨 -> reference/meaning 딕셔너리."""
    key = _LABEL_TO_KEY.get(label)
    if not key:
        return None
    return _levels[key]


def all_level_meta():
    """등급 라벨을 key로 하는 전체 참고정보 (UI가 한 번에 가져가기 좋은 형태)."""
    return {info["label"]: info for info in _levels.values()}
