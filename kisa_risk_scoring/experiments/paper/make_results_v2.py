"""2차본 results.json: 모델 비교(표본) + XGBoost 전체 실행(run_xgboost)의 위험도 산정·GPT 결과."""
import csv
import json
import statistics as st
from pathlib import Path

E = Path(__file__).resolve().parents[1]
RUN = E / "run_xgboost"
m = {p.stem.replace("metrics_", ""): json.loads(p.read_text(encoding="utf-8")) for p in (E / "results").glob("metrics_*.json")}
det = json.loads((RUN / "pred/detect_metrics.json").read_text(encoding="utf-8"))
summ = json.loads((RUN / "results/eval_summary.json").read_text(encoding="utf-8"))
b1, b2 = json.loads((RUN / "results/params.json").read_text(encoding="utf-8"))["thresholds"]
grades = {r["grade"]: r for r in csv.DictReader(open(RUN / "results/eval_by_grade.csv", encoding="utf-8-sig"))}
abl = list(csv.DictReader(open(RUN / "results/eval_ablation.csv", encoding="utf-8-sig")))
calls = json.loads((RUN / "bot/llm_stats.json").read_text(encoding="utf-8"))["calls"]
llm_model = json.loads((RUN / "bot/llm_stats.json").read_text(encoding="utf-8"))["model"]

NAMES = [("xgboost", "XGBoost"), ("extra_trees", "Extra Trees"), ("random_forest", "Random Forest"),
         ("decision_tree", "Decision Tree"), ("lightgbm_balanced", "LightGBM*")]
rows = [["Model", "Macro-F1", "Binary F1", "FPR(%)"]]
for key, name in NAMES:
    x = m[key]
    rows.append([name, f"{x['macro_f1']:.3f}", f"{x['binary_f1']:.4f}", f"{x['false_positive_rate'] * 100:.2f}"])
sqli = {k: m[k]["per_class"]["Web Attack - Sql Injection"]["f1-score"] for k, _ in NAMES[:4]}
others = [v for k, v in sqli.items() if k != "xgboost"]
xg = m["xgboost"]

EQ = {"T": "$T$", "A": "$A$", "T×A": "$T TIMES A$", "T×I": "$T TIMES I$", "T×I×A (제안)": "$T TIMES I TIMES A$ (proposed)"}
ablation = [["Ranking", "AUC", "Precision@k"]] + [[EQ[r["criterion"]], f"{float(r['auc']):.3f}", f"{float(r['precision_at_k']):.3f}"] for r in abl]
auc = {r["criterion"]: float(r["auc"]) for r in abl}
k = int(abl[0]["k"])

n_anom, n_alert = summ["anomalous_flows"], summ["alerts"]
imm, imm_share = summ["immediate_alerts"], summ["immediate_share"]
fp_total = sum(int(g["fp"]) for g in grades.values())
fp_low = int(grades["관심"]["fp"])
mean_s = st.mean(c["seconds"] for c in calls)

d = {
    "best_ko": "XGBoost",
    "llm_model": llm_model,
    "abstract": (
        "Security operations centers (SOCs) must handle large volumes of alerts, and alert fatigue delays the "
        "response to real threats. This paper proposes a SOC assistant alert bot that groups flow-level anomaly "
        "detection results into alerts by one-minute window and destination asset, scores each alert with the "
        "KISA risk model defined as the product of attack degree, impact, and asset value, and summarizes "
        "high-risk alerts with a large language model (LLM) that receives the scoring rationale as input. "
        "The bot differentiates its response into immediate notification, periodic reporting, and logging by "
        f"risk grade. On the CICIDS2017 dataset, XGBoost achieved the highest macro-F1 ({xg['macro_f1']:.3f}) among "
        f"five classifiers. In the evaluation on Thursday and Friday traffic, {n_anom:,} anomalous flows were grouped "
        f"into {n_alert} alerts, all {imm} immediate notifications ({imm_share * 100:.1f}%) were true alerts, and the "
        f"proposed ranking achieved the highest AUC ({auc['T×I×A (제안)']:.3f}) among five factor combinations."),
    "exp_setup": (
        "실험에는 CICIDS2017[7]의 GeneratedLabelledFlows 중 화~금요일 2,300,825개 flow를 사용하였다. "
        "빈 행과 깨진 레이블 문자, 12시간제로 기록된 오후 시각을 정리하였다. "
        "탐지 모델은 IP·포트·시각을 제외한 79개 특징으로 학습하고 5-fold 층화 교차 예측으로 모든 flow에 판정을 붙였다. "
        "모델 선정은 공격 flow 전부와 정상 flow 20%를 표본으로 한 같은 조건에서 5종을 비교하였으며, 충격도가 유형 판정에 "
        "의존하므로 드문 유형까지 고르게 반영하는 macro-F1을 기준으로 하였다. Table 2는 이 조건에서 측정한 5종 모델의 탐지 성능이다."),
    "table_models": rows,
    "model_result": (
        f"XGBoost가 macro-F1 {xg['macro_f1']:.3f}로 가장 우수하였고, 특히 표본이 21건인 SQL Injection의 F1이 "
        f"{sqli['xgboost']:.3f}로 다른 모델({min(others):.3f}~{max(others):.3f})보다 높았다. 전체 flow에 대한 XGBoost의 성능은 "
        f"macro-F1 {det['macro_f1']:.3f}, 오탐률 {det['false_positive_rate'] * 100:.3f}%였다. "
        "*LightGBM은 두 설정 모두 학습이 수렴하지 않았다."),
    "exp_result": (
        f"공격도 경계는 화·수요일 경보로 보정하여 $b_1$={b1:g}, $b_2$={b2:.1f}를 얻었고 목·금요일 데이터로 평가하였다. "
        "경보에 묶인 flow 중 실제 공격 비율이 0.5 이상인 경보를 참 경보로 정의하였다. "
        f"이상 flow {n_anom:,}건은 경보 {n_alert}건으로 묶였고(경보당 {summ['flows_per_alert']:.0f} flow), "
        f"즉시 알림(경계)은 {imm}건({imm_share * 100:.1f}%)으로 모두 참 경보였다. 주의·관심 등급의 정밀도는 "
        f"{float(grades['주의']['precision']):.3f}, {float(grades['관심']['precision']):.3f}이며, 오경보 {fp_total}건 중 "
        f"{fp_low}건({fp_low / fp_total * 100:.0f}%)이 가장 낮은 관심 등급에 배치되었다. "
        f"Table 3은 경보 정렬 기준별 참·오경보 구분 AUC와 상위 {k}건의 precision@k이다."),
    "table_ablation": ablation,
    "exp_result2": (
        f"제안한 $T TIMES I TIMES A$의 AUC가 {auc['T×I×A (제안)']:.3f}로 가장 높아 단일 요소나 두 요소 조합보다 "
        f"참·오경보를 잘 구분하였고, precision@k는 모든 기준에서 1.0이었다. 예측 유형 기반 위험도와 정답 "
        f"유형 기반 위험도의 Spearman 상관은 {summ['spearman_risk_vs_true_risk']:.3f}(충격도 일치율 "
        f"{summ['impact_agreement'] * 100:.1f}%)로 오분류의 영향은 작았다. GPT 요약은 건당 평균 {mean_s:.2f}초가 걸렸고, "
        f"{len(calls)}건 모두 입력 근거의 $T$, $I$, $A$ 값과 flow 수를 그대로 인용하였다."),
    "conclusion": (
        f"제안한 알림봇은 CICIDS2017 평가에서 이상 flow {n_anom:,}건을 경보 {n_alert}건으로 "
        f"묶고 즉시 알림 {imm}건을 모두 참 경보로 선별하였다. 다만 즉시 알림이 모두 웹서버 대상 DDoS였고, 감염 PC가 외부로 "
        "연결하는 Infiltration 경보는 목적지 기준 자산가치가 1로 매겨져 관심 등급에 머물러 출발지 자산의 반영이 필요하다. "
        "또한 척도와 등급 경계는 전문가 판단에 기반하며, flow 단위 교차 예측은 탐지 성능을 실제보다 높게 추정할 수 있다. "
        "향후 요일 단위 분리 평가와 실제 관제 로그 적용을 진행할 계획이다."),
}
(Path(__file__).resolve().parent / "results.json").write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
print(ablation, b1, b2, fp_total, fp_low, round(mean_s, 2))
