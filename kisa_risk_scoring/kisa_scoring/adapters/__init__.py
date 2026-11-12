"""입력 어댑터: 각 로그 형식을 공통 이벤트 스키마(base.SCHEMA_COLUMNS)로 정규화한다."""
from __future__ import annotations

from . import cicids2017, generic, suricata
from .base import BENIGN, SCHEMA_COLUMNS, SOURCES, normalize_ip, to_utc, validate_events
from .generic import load_generic
from .suricata import load_suricata, load_suricata_flows

FORMATS = ("cicids2017", "suricata", "generic")
TIME_RESOLUTION = {
    "cicids2017": cicids2017.TIME_RESOLUTION,
    "suricata": suricata.TIME_RESOLUTION,
    "generic": generic.TIME_RESOLUTION,
}


def load_events(input_format: str, paths, config, pred_col: str = "pred", fix_12h: bool | None = None,
                keep=(), require_labels: bool = False):
    """설정(ScoringConfig.input)을 반영해 입력 파일을 공통 이벤트로 읽는다."""
    inp = config.input
    tz = inp.get("timezone", "UTC")
    if input_format == "cicids2017":
        opts = inp.get("cicids2017") or {}
        fix = opts.get("fix_12h", True) if fix_12h is None else fix_12h
        frame = cicids2017.load_cicids2017(paths, fix_12h=fix)
        return cicids2017.to_events(frame, pred_col=pred_col, timezone=tz,
                                    keep=("label", *keep), require_labels=require_labels)
    if input_format == "suricata":
        return load_suricata(paths, timezone=tz)
    if input_format == "generic":
        g = inp.get("generic") or {}
        return load_generic(paths, field_map=g.get("field_map") or {}, timezone=tz,
                            fmt=g.get("format", "auto"), encoding=g.get("encoding", "utf-8-sig"),
                            default_event_type=g.get("default_event_type", "Unknown"),
                            filter=g.get("filter"), keep=keep)
    raise ValueError(f"지원하지 않는 입력 형식입니다: {input_format!r} (가능: {FORMATS})")


__all__ = ["BENIGN", "FORMATS", "SCHEMA_COLUMNS", "SOURCES", "TIME_RESOLUTION", "load_events",
           "load_generic", "load_suricata", "load_suricata_flows", "normalize_ip", "to_utc", "validate_events"]
