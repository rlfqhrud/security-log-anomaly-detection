"""KISA 위험도 = 공격도(T) × 충격도(I) × 자산가치(A) 경보 위험도 산정.

입력은 공통 이벤트 스키마(adapters.base.SCHEMA_COLUMNS)다. 예전처럼 CICIDS2017 flow 표
(timestamp, dst_ip, pred …)를 넘기면 cicids2017 어댑터로 먼저 변환한다.
"""
from __future__ import annotations

import copy
import ipaddress
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import numpy as np
import pandas as pd
import yaml

from .adapters import TIME_RESOLUTION, cicids2017
from .adapters.base import BENIGN, logger, validate_events
from .adapters.cicids2017 import normalize_label

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "default.yaml"
PROFILE_PATHS = {
    "cicids2017": CONFIG_DIR / "cicids2017.yaml",
    "suricata": DEFAULT_CONFIG_PATH,
    "generic": DEFAULT_CONFIG_PATH,
}

MODES = ("binary", "multiclass")
METHODS = ("quantile", "fixed")
LEVELS = (1, 2, 3)
UNKNOWN_ASSET = "미등록 자산"
MAX_REFS = 5

ALERT_COLUMNS = [
    "window_start", "dst_ip", "asset_name", "flow_count", "first_seen", "last_seen",
    "dominant_type", "impact_type", "attack_types", "src_ips",
    "T", "I", "A", "risk", "grade", "action", "rationale",
    "source", "impact_basis", "raw_refs", "signatures",
]
TRUE_COLUMNS = ["true_attack_ratio", "true_types", "true_impact"]
RECORD_FIELDS = [
    "window_start", "first_seen", "last_seen", "dst_ip", "asset_name", "flow_count",
    "dominant_type", "impact_type", "attack_types", "T", "I", "A", "risk",
    "grade", "action", "rationale", "src_ips",
    "source", "event_types", "raw_refs", "signatures", "timezone",
]
_BASIS_TEXT = {
    "category": "근거: Suricata category 매핑",
    "severity": "근거: 원본 severity 매핑",
    "severity_numeric": "근거: 원본 severity 구간",
    "event_type": "근거: event_type 매핑",
    "default": "미매핑 유형 → 기본값",
}


def _is_level(v) -> bool:
    return isinstance(v, (int, np.integer)) and not isinstance(v, bool) and int(v) in LEVELS


def severity_key(v) -> str | None:
    """severity 값 비교용 키: 1, 1.0, "1" → "1"; "High" → "high"; 결측 → None."""
    if v is None or (not isinstance(v, str) and pd.isna(v)):
        return None
    if isinstance(v, (float, np.floating)) and float(v).is_integer():
        v = int(v)
    s = str(v).strip().lower()
    return s or None


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _read_yaml(path: Path, _seen: tuple = ()) -> dict:
    path = Path(path).resolve()
    if path in _seen:
        raise ValueError(f"설정 상속이 순환합니다: {[str(p) for p in _seen + (path,)]}")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    parent = data.pop("extends", None)
    if parent:
        data = _deep_merge(_read_yaml(path.parent / parent, _seen + (path,)), data)
    return data


@dataclass
class ScoringConfig:
    """설정 파일(config/*.yaml) 내용. 각 값의 근거는 default.yaml 주석 참고."""

    mode: str = "multiclass"
    window: str = "1min"
    attack_degree: dict = field(default_factory=lambda: {"method": "quantile", "quantiles": [0.5, 0.9], "thresholds": None})
    impact: dict = field(default_factory=lambda: {"default": 2, "min_share": 0.05, "levels": {}})
    asset_value: dict = field(default_factory=lambda: {"default": 1, "assets": {}})
    grades: dict = field(default_factory=dict)
    timezone: str = "UTC"
    input: dict = field(default_factory=lambda: {"timezone": "UTC"})

    @classmethod
    def from_dict(cls, d: dict) -> "ScoringConfig":
        d = copy.deepcopy(d)
        cfg = cls(
            mode=d.get("mode", "multiclass"),
            window=str(d.get("window", "1min")),
            attack_degree=d.get("attack_degree") or {},
            impact=d.get("impact") or {},
            asset_value=d.get("asset_value") or {},
            grades=d.get("grades") or {},
            timezone=str(d.get("timezone", "UTC")),
            input=d.get("input") or {"timezone": "UTC"},
        )
        # 레이블·IP·severity 키를 데이터와 같은 형태로 맞춘다.
        imp = cfg.impact
        imp["levels"] = {normalize_label(k): v for k, v in (imp.get("levels") or {}).items()}
        sur = imp.setdefault("suricata", {}) or {}
        imp["suricata"] = {
            "severity": {severity_key(k): v for k, v in (sur.get("severity") or {}).items()},
            "category": {normalize_label(k): v for k, v in (sur.get("category") or {}).items()},
        }
        gen = imp.setdefault("generic", {}) or {}
        imp["generic"] = {
            "levels": {normalize_label(k): v for k, v in (gen.get("levels") or {}).items()},
            "severity": {severity_key(k): v for k, v in (gen.get("severity") or {}).items()},
            "severity_numeric": list(gen.get("severity_numeric") or []),
        }
        cfg.asset_value["assets"] = {str(k).strip(): v for k, v in (cfg.asset_value.get("assets") or {}).items()}
        cfg.validate()
        return cfg

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScoringConfig":
        """YAML을 읽는다. `extends: 다른.yaml`이 있으면 그 파일을 먼저 읽고 덮어쓴다."""
        return cls.from_dict(_read_yaml(Path(path)))

    @classmethod
    def default(cls, input_format: str = "cicids2017") -> "ScoringConfig":
        """입력 형식별 기본 프로필. cicids2017 → config/cicids2017.yaml, 그 외 → config/default.yaml."""
        if input_format not in PROFILE_PATHS:
            raise ValueError(f"지원하지 않는 입력 형식입니다: {input_format!r}")
        return cls.from_yaml(PROFILE_PATHS[input_format])

    def validate(self) -> "ScoringConfig":
        if self.mode not in MODES:
            raise ValueError(f"mode는 {MODES} 중 하나여야 합니다: {self.mode!r}")
        try:
            if pd.Timedelta(self.window) <= pd.Timedelta(0):
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"window가 올바른 기간 문자열이 아닙니다: {self.window!r}") from None
        for name, tz in (("timezone", self.timezone), ("input.timezone", (self.input or {}).get("timezone", "UTC"))):
            try:
                ZoneInfo(str(tz))
            except (ZoneInfoNotFoundError, ValueError):
                raise ValueError(f"{name}가 IANA 시간대 이름이 아닙니다: {tz!r} (예: Asia/Seoul, UTC)") from None

        ad = self.attack_degree
        method = ad.get("method")
        if method not in METHODS:
            raise ValueError(f"attack_degree.method는 {METHODS} 중 하나여야 합니다: {method!r}")
        if method == "quantile":
            q = ad.get("quantiles")
            if not (isinstance(q, (list, tuple)) and len(q) == 2 and 0 <= q[0] <= q[1] <= 1):
                raise ValueError(f"attack_degree.quantiles는 0≤q1≤q2≤1인 두 값이어야 합니다: {q!r}")
        else:
            t = ad.get("thresholds")
            if not (isinstance(t, (list, tuple)) and len(t) == 2 and t[0] <= t[1]):
                raise ValueError(f"attack_degree.thresholds는 b1≤b2인 두 값이어야 합니다: {t!r}")

        imp = self.impact
        if not _is_level(imp.get("default")):
            raise ValueError(f"impact.default는 1~3이어야 합니다: {imp.get('default')!r}")
        ms = imp.get("min_share", 0)
        if not (isinstance(ms, (int, float)) and 0 <= ms <= 1):
            raise ValueError(f"impact.min_share는 0~1이어야 합니다: {ms!r}")
        tables = {"impact.levels": imp.get("levels") or {}}
        for fmt in ("suricata", "generic"):
            for key, table in (imp.get(fmt) or {}).items():
                if isinstance(table, dict):
                    tables[f"impact.{fmt}.{key}"] = table
        for where, table in tables.items():
            for label, lv in table.items():
                if not _is_level(lv):
                    raise ValueError(f"충격도 등급은 1~3이어야 합니다: {where}[{label}]={lv!r}")
        for b in (imp.get("generic") or {}).get("severity_numeric") or []:
            if not (isinstance(b, dict) and isinstance(b.get("min"), (int, float)) and _is_level(b.get("level"))):
                raise ValueError(f"impact.generic.severity_numeric 항목은 {{min: 숫자, level: 1~3}}이어야 합니다: {b!r}")

        av = self.asset_value
        if not _is_level(av.get("default")):
            raise ValueError(f"asset_value.default는 1~3이어야 합니다: {av.get('default')!r}")
        for key, info in (av.get("assets") or {}).items():
            try:
                ipaddress.ip_network(key, strict=True)
            except ValueError as e:
                raise ValueError(f"자산 키가 IP/CIDR 형식이 아닙니다: {key!r} ({e})") from None
            if not (isinstance(info, dict) and _is_level(info.get("level"))):
                raise ValueError(f"자산가치 등급은 1~3이어야 합니다: {key}={info!r}")

        if self.mode not in self.grades:
            raise ValueError(f"grades에 '{self.mode}' 등급표가 없습니다.")
        for mode, table in self.grades.items():
            if not table:
                raise ValueError(f"grades.{mode}가 비어 있습니다.")
            scores = []
            for g in table:
                if not all(k in g for k in ("name", "min_score", "action")):
                    raise ValueError(f"grades.{mode} 항목에 name/min_score/action이 필요합니다: {g!r}")
                scores.append(g["min_score"])
            if any(a <= b for a, b in zip(scores, scores[1:])):
                raise ValueError(f"grades.{mode}는 min_score 내림차순이어야 합니다: {scores}")
            if scores[-1] > 1:
                raise ValueError(f"grades.{mode}의 마지막 등급 min_score는 1 이하여야 합니다: {scores[-1]}")
        return self


class _AssetIndex:
    """IP/CIDR 자산표. 여러 대역에 걸리면 가장 긴 prefix가 우선한다."""

    def __init__(self, asset_value: dict):
        self.default = int(asset_value["default"])
        nets = []
        for key, info in (asset_value.get("assets") or {}).items():
            net = ipaddress.ip_network(key, strict=True)
            nets.append((net, int(info["level"]), str(info.get("name", key))))
        self.nets = sorted(nets, key=lambda x: -x[0].prefixlen)
        self._cache: dict[str, tuple[int, str]] = {}

    def lookup(self, ip) -> tuple[int, str]:
        key = str(ip).strip()
        if key not in self._cache:
            result = (self.default, UNKNOWN_ASSET)
            try:
                addr = ipaddress.ip_address(key)
                for net, level, name in self.nets:
                    if addr.version == net.version and addr in net:
                        result = (level, name)
                        break
            except ValueError:
                pass
            self._cache[key] = result
        return self._cache[key]


@dataclass
class RiskScorer:
    """공통 이벤트 → (창, 목적지 IP) 경보 → 위험도·등급."""

    config: ScoringConfig
    thresholds_: tuple[float, float] | None = None
    fitted_on_: dict | None = None

    # ------------------------------------------------------------------ 설정 조회
    @property
    def mode(self) -> str:
        return self.config.mode

    @property
    def grade_table(self) -> list[dict]:
        return self.config.grades[self.mode]

    def impact_level(self, attack_type: str) -> int:
        """CICIDS2017 레이블 표 기준 충격도 (정답 충격도 계산에도 쓴다)."""
        imp = self.config.impact
        return int(imp["levels"].get(attack_type, imp["default"]))

    def impact_for(self, source: str, event_type: str, severity) -> tuple[int, str]:
        """이벤트 하나의 충격도와 근거.

        cicids2017 : impact.levels
        suricata   : impact.suricata.category → impact.suricata.severity
        generic    : impact.generic.levels → .severity → .severity_numeric
        어디에도 없으면 (impact.default, "default").
        """
        imp = self.config.impact
        sev = severity_key(severity)
        if source == "suricata":
            sur = imp.get("suricata") or {}
            if event_type in sur.get("category", {}):
                return int(sur["category"][event_type]), "category"
            if sev in sur.get("severity", {}):
                return int(sur["severity"][sev]), "severity"
        elif source == "generic":
            gen = imp.get("generic") or {}
            if event_type in gen.get("levels", {}):
                return int(gen["levels"][event_type]), "event_type"
            if sev in gen.get("severity", {}):
                return int(gen["severity"][sev]), "severity"
            try:
                num = float(sev) if sev is not None else None
            except ValueError:
                num = None
            if num is not None:
                for b in sorted(gen.get("severity_numeric") or [], key=lambda b: -b["min"]):
                    if num >= b["min"]:
                        return int(b["level"]), "severity_numeric"
        elif event_type in imp["levels"]:
            return int(imp["levels"][event_type]), "label"
        return int(imp["default"]), "default"

    def asset(self, ip: str) -> tuple[int, str]:
        return _AssetIndex(self.config.asset_value).lookup(ip)

    def grade_of(self, risk: int) -> dict:
        for g in self.grade_table:
            if risk >= g["min_score"]:
                return g
        return self.grade_table[-1]

    # ------------------------------------------------------------------ 입력 → 공통 이벤트
    @staticmethod
    def _to_anomalous(s: pd.Series) -> pd.Series:
        """bool·숫자는 그대로(0이 아니면 이상), 문자열은 BENIGN이 아니면 이상."""
        if pd.api.types.is_bool_dtype(s):
            return s.fillna(False).astype(bool)
        if pd.api.types.is_numeric_dtype(s):
            return s.fillna(0).astype(float) != 0
        return normalize_label(s) != BENIGN

    def to_events(self, df: pd.DataFrame, pred_col: str = "pred", true_col: str | None = None) -> pd.DataFrame:
        """공통 스키마면 그대로, CICIDS2017 flow 표면 어댑터로 변환한다."""
        if "event_type" in df.columns and "source" in df.columns:
            validate_events(df)
            return df
        keep = ["label"] + ([true_col] if true_col else [])
        return cicids2017.to_events(df, pred_col=pred_col, timezone=(self.config.input or {}).get("timezone", "UTC"),
                                    keep=keep, require_labels=self.mode == "multiclass")

    def _check_window(self, sources) -> None:
        w = pd.Timedelta(self.config.window)
        for src in sources:
            res = TIME_RESOLUTION.get(src)
            if res and w < pd.Timedelta(res):
                logger.warning("window=%s가 %s 입력의 시각 해상도(%s)보다 작습니다. 창이 쪼개져 공격도가 낮게 나옵니다.",
                               self.config.window, src, res)

    def _windows(self, utc_ts: pd.Series) -> pd.Series:
        """창 경계는 UTC에서 자른 뒤 출력 시간대로 바꾼다(서머타임 전환에도 안전)."""
        return utc_ts.dt.tz_convert("UTC").dt.floor(self.config.window).dt.tz_convert(self.config.timezone)

    def _prepare(self, df: pd.DataFrame, pred_col: str = "pred", true_col: str | None = None) -> pd.DataFrame:
        ev = self.to_events(df, pred_col, true_col).copy()
        if true_col is not None and true_col not in ev.columns:
            raise ValueError(f"정답 컬럼이 없습니다: {true_col}")
        self._check_window(ev["source"].unique())
        ev["_window"] = self._windows(ev["timestamp"])
        ev["timestamp"] = ev["timestamp"].dt.tz_convert(self.config.timezone)
        ev["_type"] = normalize_label(ev["event_type"])
        ev["_is_anom"] = ev["_type"] != BENIGN
        if self.mode == "binary":
            ev.loc[ev["source"] == "cicids2017", "_type"] = "Anomaly"
        else:
            self._assign_impact(ev)
        return ev

    def _assign_impact(self, ev: pd.DataFrame) -> None:
        anom = ev["_is_anom"].to_numpy()
        sub = ev.loc[anom]
        keys = list(zip(sub["source"], sub["_type"], sub["severity_hint"].map(severity_key)))
        cache = {k: self.impact_for(*k) for k in set(keys)}
        ev["_I"] = pd.Series(pd.NA, index=ev.index, dtype="Int64")
        ev["_I_basis"] = None
        ev.loc[anom, "_I"] = [cache[k][0] for k in keys]
        ev.loc[anom, "_I_basis"] = [cache[k][1] for k in keys]
        unmapped = Counter((k[0], k[1]) for k in keys if cache[k][1] == "default")
        if unmapped:
            listing = ", ".join(f"{s}:{t!r}({n}건)" for (s, t), n in unmapped.most_common(10))
            logger.warning("충격도 매핑표에 없는 유형은 기본값 I=%s로 처리합니다: %s",
                           self.config.impact["default"], listing)

    def count_anomalous(self, df: pd.DataFrame, pred_col: str = "pred") -> int:
        return int(self._prepare(df, pred_col)["_is_anom"].sum())

    # ------------------------------------------------------------------ 집계
    def _window_impact(self, types: pd.Series, min_share: float | None = None,
                       levels: pd.Series | None = None) -> tuple[int, str]:
        """창 안 유형 분포로 충격도를 정한다.

        비중이 min_share 이상인 유형 중 심각도가 가장 높은 유형(동률이면 비중이 큰 쪽).
        후보가 없으면 최다 유형. 순수 max는 오분류 이벤트 1건이 경보 전체를 3으로 올린다.
        levels: 이벤트별 충격도(같은 유형 안에서 다르면 최댓값). 없으면 레이블 표를 쓴다.
        """
        if min_share is None:
            min_share = float(self.config.impact.get("min_share", 0))
        types = types.astype(str)
        if levels is None:
            levels = types.map(self.impact_level)
        tab = (pd.DataFrame({"type": types.to_numpy(), "level": np.asarray(levels, dtype=int)})
               .groupby("type", sort=False).agg(count=("level", "size"), level=("level", "max")).reset_index())
        tab["share"] = tab["count"] / tab["count"].sum()
        tab = tab.sort_values(["count", "type"], ascending=[False, True], kind="stable")
        cand = tab[tab["share"] >= min_share - 1e-12]
        if cand.empty:
            top = tab.iloc[0]
        else:
            top = cand.sort_values(["level", "share", "type"], ascending=[False, False, True], kind="stable").iloc[0]
        return int(top["level"]), str(top["type"])

    @staticmethod
    def _sample_refs(grp: pd.DataFrame, impact_type, type_order) -> list[str]:
        """근거 인용용 raw_ref 최대 5개: 충격도 유형 첫 이벤트 → 유형별 첫 이벤트 → 시간순."""
        refs = grp["raw_ref"].astype(str)
        firsts = refs.groupby(grp["_type"].to_numpy(), sort=False).first()
        picks = []
        if impact_type is not None and not pd.isna(impact_type) and impact_type in firsts.index:
            picks.append(firsts[impact_type])
        picks += [firsts[t] for t in type_order if t in firsts.index]
        picks += refs.head(MAX_REFS * 2).tolist()
        return list(dict.fromkeys(picks))[:MAX_REFS]

    def _aggregate(self, ev: pd.DataFrame, true_col: str | None = None) -> pd.DataFrame:
        anom = ev[ev["_is_anom"]]
        has_src = "src_ip" in anom.columns and anom["src_ip"].notna().any()
        has_sig = "signature" in anom.columns and anom["signature"].notna().any()
        rows = []
        for (win, ip), grp in anom.groupby(["_window", "dst_ip"], sort=True):
            counts = grp["_type"].value_counts()
            row: dict[str, Any] = {
                "window_start": win,
                "dst_ip": ip,
                "flow_count": len(grp),
                "first_seen": grp["timestamp"].min(),
                "last_seen": grp["timestamp"].max(),
                "attack_types": ";".join(counts.index.astype(str)),
                "dominant_type": str(counts.index[0]),
                "source": ";".join(sorted(grp["source"].astype(str).unique())),
            }
            if self.mode == "multiclass":
                row["I"], row["impact_type"] = self._window_impact(grp["_type"], levels=grp["_I"].astype(int))
                chosen = grp[(grp["_type"] == row["impact_type"]) & (grp["_I"] == row["I"])]
                row["impact_basis"] = chosen["_I_basis"].iloc[0]
            else:
                row["I"], row["impact_type"], row["impact_basis"] = pd.NA, pd.NA, pd.NA
            row["raw_refs"] = self._sample_refs(grp, row["impact_type"], counts.index)
            row["src_ips"] = ";".join(grp["src_ip"].dropna().astype(str).value_counts().index[:5]) if has_src else pd.NA
            row["signatures"] = grp["signature"].dropna().astype(str).value_counts().index[:MAX_REFS].tolist() if has_sig else pd.NA
            if true_col is not None:
                truth = grp[true_col]
                is_attack = self._to_anomalous(truth)
                row["true_attack_ratio"] = float(is_attack.mean())
                labels = normalize_label(truth) if not pd.api.types.is_numeric_dtype(truth) else truth.astype(str)
                row["true_types"] = ";".join(labels.value_counts().index.astype(str))
                if self.mode == "multiclass":
                    row["true_impact"] = self._window_impact(labels[is_attack])[0] if is_attack.any() else 0
            rows.append(row)

        cols = ["window_start", "dst_ip", "flow_count", "first_seen", "last_seen", "I", "impact_type",
                "attack_types", "dominant_type", "src_ips", "source", "impact_basis", "raw_refs", "signatures"]
        if true_col is not None:
            cols += ["true_attack_ratio", "true_types"] + (["true_impact"] if self.mode == "multiclass" else [])
        alerts = pd.DataFrame(rows, columns=cols)
        alerts["I"] = alerts["I"].astype("Int64")
        alerts["flow_count"] = alerts["flow_count"].astype(int)
        return alerts

    def window_counts(self, events: pd.DataFrame) -> pd.DataFrame:
        """(window_start, dst_ip)별 이벤트 수 — Suricata flow 같은 맥락 이벤트 집계용."""
        if events.empty:
            return pd.DataFrame(columns=["window_start", "dst_ip", "count"])
        win = self._windows(events["timestamp"])
        return (pd.DataFrame({"window_start": win, "dst_ip": events["dst_ip"].to_numpy()})
                .groupby(["window_start", "dst_ip"]).size().rename("count").reset_index())

    def attach_context(self, alerts: pd.DataFrame, events: pd.DataFrame, column: str = "context_flows") -> pd.DataFrame:
        """경보에 같은 창·목적지의 맥락 이벤트 수를 붙인다(위험도에는 반영하지 않음)."""
        counts = self.window_counts(events).rename(columns={"count": column})
        out = alerts.merge(counts, on=["window_start", "dst_ip"], how="left")
        out[column] = out[column].fillna(0).astype(int)
        return out

    # ------------------------------------------------------------------ 공격도 경계 학습
    def fit(self, df: pd.DataFrame | None = None, pred_col: str = "pred") -> "RiskScorer":
        ad = self.config.attack_degree
        if ad["method"] == "fixed":
            b1, b2 = ad["thresholds"]
            self.thresholds_ = (float(b1), float(b2))
            self.fitted_on_ = {"method": "fixed", "thresholds": [float(b1), float(b2)]}
            return self

        if df is None:
            raise ValueError("quantile 방식은 보정 데이터가 필요합니다.")
        ev = self._prepare(df, pred_col)
        alerts = self._aggregate(ev)
        if alerts.empty:
            raise ValueError("보정 데이터에 이상 판정 이벤트가 없어 공격도 경계를 학습할 수 없습니다.")
        n = alerts["flow_count"].to_numpy()
        q1, q2 = (float(q) for q in ad["quantiles"])
        b1, b2 = np.quantile(n, [q1, q2])
        self.thresholds_ = (float(b1), float(b2))
        self.fitted_on_ = {
            "method": "quantile",
            "quantiles": [q1, q2],
            "n_alerts": int(len(n)),
            "count_min": int(n.min()),
            "count_median": float(np.median(n)),
            "count_max": int(n.max()),
            "sources": sorted(ev["source"].astype(str).unique().tolist()),
        }
        return self

    def save_params(self, path: str | Path) -> None:
        if self.thresholds_ is None:
            raise RuntimeError("fit() 또는 load_params()를 먼저 실행하세요.")
        params = {
            "thresholds": list(self.thresholds_),
            "fitted_on": self.fitted_on_,
            "window": self.config.window,
            "mode": self.mode,
            "timezone": self.config.timezone,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(params, f, ensure_ascii=False, indent=2)

    def load_params(self, path: str | Path) -> "RiskScorer":
        with open(path, encoding="utf-8") as f:
            params = json.load(f)
        for key in ("mode", "window"):
            current = getattr(self.config, key)
            if params.get(key) != current:
                raise ValueError(f"params의 {key}={params.get(key)!r}가 현재 설정 {current!r}와 다릅니다.")
        b1, b2 = params["thresholds"]
        self.thresholds_ = (float(b1), float(b2))
        self.fitted_on_ = params.get("fitted_on")
        return self

    # ------------------------------------------------------------------ 위험도 산정
    def score(self, df: pd.DataFrame, pred_col: str = "pred", true_col: str | None = None) -> pd.DataFrame:
        if self.thresholds_ is None:
            raise RuntimeError("공격도 경계가 없습니다. fit() 또는 load_params()를 먼저 실행하세요.")
        ev = self._prepare(df, pred_col, true_col)
        fitted_sources = set((self.fitted_on_ or {}).get("sources") or [])
        new_sources = set(ev["source"].astype(str).unique()) - fitted_sources
        if fitted_sources and new_sources:
            logger.warning("공격도 경계는 %s 입력으로 보정되었는데 %s 입력에 적용합니다. 건수 분포가 다르므로 같은 형식으로 보정하세요.",
                           sorted(fitted_sources), sorted(new_sources))
        alerts = self._aggregate(ev, true_col)

        b1, b2 = self.thresholds_
        n = alerts["flow_count"].to_numpy()
        alerts["T"] = np.select([n <= b1, n <= b2], [1, 2], default=3).astype(int)
        index = _AssetIndex(self.config.asset_value)
        assets = [index.lookup(ip) for ip in alerts["dst_ip"]]
        alerts["A"] = np.array([a for a, _ in assets], dtype=int)
        alerts["asset_name"] = [name for _, name in assets]

        if self.mode == "binary":
            alerts["risk"] = alerts["T"] * alerts["A"]
            formula = "T×A"
        else:
            alerts["risk"] = (alerts["T"] * alerts["I"].astype(int) * alerts["A"]).astype(int)
            formula = "T×I×A"

        grades = [self.grade_of(int(r)) for r in alerts["risk"]]
        alerts["grade"] = [g["name"] for g in grades]
        alerts["action"] = [g["action"] for g in grades]
        window = self.config.window
        alerts["rationale"] = [self._rationale(r, formula, window) for r in alerts.itertuples(index=False)]

        alerts = alerts.sort_values(
            ["risk", "flow_count", "window_start", "dst_ip"],
            ascending=[False, False, True, True], kind="stable",
        ).reset_index(drop=True)
        extra = [c for c in TRUE_COLUMNS if c in alerts.columns]
        return alerts[ALERT_COLUMNS + extra]

    def _rationale(self, r, formula: str, window: str) -> str:
        unit = "flow" if r.source == "cicids2017" else "이벤트"
        parts = [f"공격도 T={r.T} ({window} 동안 이상 {unit} {r.flow_count}건)"]
        if self.mode == "multiclass":
            basis = _BASIS_TEXT.get(r.impact_basis)
            parts.append(f"충격도 I={r.I} (유형: {r.impact_type}" + (f", {basis})" if basis else ")"))
        parts.append(f"자산가치 A={r.A} ({r.asset_name})")
        return f"위험도 {r.risk} = {formula}; " + ", ".join(parts)

    # ------------------------------------------------------------------ 알림봇 연동
    @staticmethod
    def to_alert_records(alerts: pd.DataFrame, min_grade_score: int = 1) -> list[dict]:
        """알림봇·LLM 요약에 넘길 JSON 직렬화 가능한 레코드 목록.

        risk가 min_grade_score 이상인 경보만 포함한다(예: 등급표의 '경계' min_score를 넣으면
        즉시 알림 대상만 남는다). 시각은 설정 timezone 기준 "%Y-%m-%d %H:%M:%S"이고
        timezone 필드에 그 이름을 적는다. raw_refs는 원본 근거(파일:줄 또는 이벤트 ID) 최대 5개.
        """
        sel = alerts[alerts["risk"] >= min_grade_score]
        records = []
        for _, row in sel.iterrows():
            rec = {}
            for key in RECORD_FIELDS:
                if key == "event_types":
                    v = row.get("attack_types")
                    rec[key] = str(v).split(";") if isinstance(v, str) and v else []
                    continue
                if key == "timezone":
                    ts = row.get("window_start")
                    rec[key] = str(ts.tz) if isinstance(ts, pd.Timestamp) and ts.tz is not None else None
                    continue
                v = row.get(key, None)
                if isinstance(v, (list, tuple, np.ndarray)):
                    rec[key] = [str(x) for x in v]
                elif v is None or pd.isna(v):
                    rec[key] = None
                elif isinstance(v, pd.Timestamp):
                    rec[key] = v.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(v, np.integer):
                    rec[key] = int(v)
                elif isinstance(v, np.floating):
                    rec[key] = float(v)
                else:
                    rec[key] = v
            records.append(rec)
        return records
