"""경보 위험도 평가: 등급별 정밀도, 정렬 기준 비교(ablation), 그림."""
from __future__ import annotations

import warnings
from pathlib import Path

import numpy as np
import pandas as pd

from .scoring import RiskScorer

try:
    from sklearn.metrics import roc_auc_score
except ImportError:  # 예: Windows 애플리케이션 제어 정책이 scipy DLL을 차단한 환경
    def roc_auc_score(y_true, y_score) -> float:
        """sklearn과 같은 값: Mann-Whitney U / (n_pos × n_neg), 동점은 평균 순위."""
        y = np.asarray(y_true, dtype=bool)
        ranks = pd.Series(np.asarray(y_score, dtype=float)).rank(method="average").to_numpy()
        n_pos, n_neg = int(y.sum()), int((~y).sum())
        return (ranks[y].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)

try:
    from scipy.stats import spearmanr as _scipy_spearmanr

    def _spearman(a, b) -> float:
        return float(_scipy_spearmanr(a, b).statistic)
except ImportError:
    def _spearman(a, b) -> float:
        """scipy와 같은 값: 평균 순위의 Pearson 상관."""
        ra = pd.Series(np.asarray(a, dtype=float)).rank()
        rb = pd.Series(np.asarray(b, dtype=float)).rank()
        if ra.nunique() < 2 or rb.nunique() < 2:
            return float("nan")
        return float(np.corrcoef(ra, rb)[0, 1])

PROPOSED_SUFFIX = " (제안)"
_KOREAN_FONTS = ["NanumGothic", "Noto Sans CJK KR", "Noto Sans KR", "Malgun Gothic", "AppleGothic", "Gulim"]


def _rank_order(score: np.ndarray, alerts: pd.DataFrame) -> np.ndarray:
    """정렬 기준 내림차순, 동점은 flow_count 내림차순 → window_start 오름차순."""
    key = pd.DataFrame({
        "s": score,
        "n": alerts["flow_count"].to_numpy(),
        "w": alerts["window_start"].to_numpy(),
        "ip": alerts["dst_ip"].to_numpy(),
    })
    return key.sort_values(["s", "n", "w", "ip"], ascending=[False, False, True, True], kind="stable").index.to_numpy()


def _safe_div(a: float, b: float) -> float:
    return float(a) / float(b) if b else float("nan")


def evaluate(alerts: pd.DataFrame, scorer: RiskScorer, n_anomalous_flows: int, tp_ratio: float = 0.5) -> dict:
    """경보 표를 평가한다. 참 경보(TP) = true_attack_ratio ≥ tp_ratio."""
    if "true_attack_ratio" not in alerts.columns:
        raise ValueError("평가하려면 score(..., true_col=...)로 만든 경보가 필요합니다.")
    alerts = alerts.reset_index(drop=True)
    mode = scorer.mode
    grades = scorer.grade_table
    is_tp = (alerts["true_attack_ratio"] >= tp_ratio).to_numpy()
    n_alerts = len(alerts)

    # --- 등급별
    rows = []
    for g in grades:
        m = (alerts["grade"] == g["name"]).to_numpy()
        n, tp = int(m.sum()), int((m & is_tp).sum())
        rows.append({"grade": g["name"], "alerts": n, "tp": tp, "fp": n - tp,
                     "share": _safe_div(n, n_alerts), "precision": _safe_div(tp, n)})
    by_grade = pd.DataFrame(rows)

    immediate_names = [g["name"] for g in grades if g.get("immediate", False)]
    imm = alerts["grade"].isin(immediate_names).to_numpy()
    k = int(imm.sum())
    summary = {
        "mode": mode,
        "anomalous_flows": int(n_anomalous_flows),
        "alerts": n_alerts,
        "flows_per_alert": _safe_div(n_anomalous_flows, n_alerts),
        "immediate_grades": immediate_names,
        "immediate_alerts": k,
        "immediate_share": _safe_div(k, n_alerts),
        "overall_alert_precision": _safe_div(is_tp.sum(), n_alerts),
        "immediate_precision": _safe_div((imm & is_tp).sum(), k),
        "tp_ratio_threshold": float(tp_ratio),
    }

    # --- 정렬 기준 비교
    T = alerts["T"].to_numpy(dtype=float)
    A = alerts["A"].to_numpy(dtype=float)
    if mode == "multiclass":
        I = alerts["I"].astype(float).to_numpy()
        criteria = [("T", T), ("A", A), ("T×A", T * A), ("T×I", T * I),
                    ("T×I×A" + PROPOSED_SUFFIX, alerts["risk"].to_numpy(dtype=float))]
    else:
        criteria = [("T", T), ("A", A), ("T×A" + PROPOSED_SUFFIX, alerts["risk"].to_numpy(dtype=float))]

    both = 0 < is_tp.sum() < n_alerts
    abl = []
    for name, s in criteria:
        auc = float(roc_auc_score(is_tp, s)) if both else float("nan")
        p_at_k = float(is_tp[_rank_order(s, alerts)[:k]].mean()) if k else float("nan")
        abl.append({"criterion": name, "auc": auc, "k": k, "precision_at_k": p_at_k})
    ablation = pd.DataFrame(abl)

    # --- 예측 충격도 vs 정답 충격도 (TP 경보)
    if mode == "multiclass" and "true_impact" in alerts.columns:
        tp = alerts[is_tp & (alerts["true_impact"] > 0).to_numpy()]
        summary["tp_alerts_with_true_impact"] = int(len(tp))
        if len(tp):
            risk_true = tp["T"] * tp["true_impact"] * tp["A"]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                rho = _spearman(tp["risk"], risk_true) if len(tp) > 1 else float("nan")
            summary["spearman_risk_vs_true_risk"] = float(rho)
            summary["impact_agreement"] = float((tp["I"].astype(int) == tp["true_impact"]).mean())
        else:
            summary["spearman_risk_vs_true_risk"] = float("nan")
            summary["impact_agreement"] = float("nan")

    return {"summary": summary, "by_grade": by_grade, "ablation": ablation}


def _korean_font() -> str | None:
    from matplotlib import font_manager

    installed = {f.name for f in font_manager.fontManager.ttflist}
    return next((f for f in _KOREAN_FONTS if f in installed), None)


def plot_results(result: dict, path: str | Path) -> None:
    """왼쪽: 등급별 참/오경보 누적 막대 + 정밀도, 오른쪽: 정렬 기준별 AUC."""
    import matplotlib
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    rc = {"axes.unicode_minus": False}
    font = _korean_font()
    if font:
        rc["font.family"] = font

    with matplotlib.rc_context(rc):
        fig = Figure(figsize=(11, 4.2))
        FigureCanvasAgg(fig)
        ax1, ax2 = fig.subplots(1, 2, gridspec_kw={"width_ratios": [1, 1.15]})

        bg = result["by_grade"]
        x = np.arange(len(bg))
        ax1.bar(x, bg["tp"], color="#2f6db5", label="참 경보")
        ax1.bar(x, bg["fp"], bottom=bg["tp"], color="#e0a040", label="오경보")
        top = max(int(bg["alerts"].max()), 1)
        for xi, (n, p) in enumerate(zip(bg["alerts"], bg["precision"])):
            text = "-" if pd.isna(p) else f"{p * 100:.1f}%"
            ax1.text(xi, n + top * 0.02, text, ha="center", va="bottom", fontsize=9)
        ax1.set_xticks(x, bg["grade"])
        ax1.set_ylim(0, top * 1.15)
        ax1.set_ylabel("경보 수")
        ax1.set_title("등급별 경보와 정밀도")
        ax1.legend(frameon=False)

        ab = result["ablation"]
        y = np.arange(len(ab))
        auc = ab["auc"].fillna(0).to_numpy()
        colors = ["#c0392b" if c.endswith(PROPOSED_SUFFIX) else "#9aa5b1" for c in ab["criterion"]]
        ax2.barh(y, auc, color=colors)
        xmin = 0.4
        for yi, v in zip(y, ab["auc"]):
            if pd.isna(v):
                pos, text = xmin, "N/A"
            elif v < xmin:  # 축 범위 밖: 막대는 잘리므로 값만 축 안쪽에 표시
                pos, text = xmin, f"{v:.3f} (<{xmin})"
            else:
                pos, text = v, f"{v:.3f}"
            ax2.text(pos + 0.005, yi, text, va="center", fontsize=9)
        ax2.set_yticks(y, ab["criterion"])
        ax2.invert_yaxis()
        ax2.set_xlim(xmin, 1.05)
        ax2.axvline(0.5, color="#666", lw=0.8, ls="--")
        ax2.set_xlabel("AUC (참 경보 vs 오경보)")
        ax2.set_title("정렬 기준별 구분력")

        fig.tight_layout()
        fig.savefig(path, dpi=200)
