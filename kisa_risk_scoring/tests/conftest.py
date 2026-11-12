import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kisa_scoring import RiskScorer, ScoringConfig  # noqa: E402

WEB = "192.168.10.50"
DC = "192.168.10.3"
UNREGISTERED = "10.0.0.99"


@pytest.fixture
def make_scorer():
    """기본 설정에 fixed thresholds [2, 5]를 넣은 RiskScorer를 만든다."""

    def _make(mode: str = "multiclass", min_share: float | None = None) -> RiskScorer:
        cfg = ScoringConfig.default()
        cfg.mode = mode
        cfg.attack_degree = {"method": "fixed", "thresholds": [2, 5]}
        if min_share is not None:
            cfg.impact["min_share"] = min_share
        cfg.validate()
        return RiskScorer(cfg).fit()

    return _make


@pytest.fixture
def flows():
    """(분 문자열, dst_ip, pred, label) 목록 → flow DataFrame."""

    def _flows(rows):
        df = pd.DataFrame(rows, columns=["timestamp", "dst_ip", "pred", "label"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["src_ip"] = "205.174.165.73"
        return df

    return _flows
