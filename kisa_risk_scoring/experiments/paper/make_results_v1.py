"""1차본 results.json: 모델 비교는 실측값(experiments/results/metrics_*.json), 위험도 산정은 빈칸."""
import json
from pathlib import Path

R = Path(__file__).resolve().parents[1] / "results"
m = {p.stem.replace("metrics_", ""): json.loads(p.read_text(encoding="utf-8")) for p in R.glob("metrics_*.json")}
NAMES = [("xgboost", "XGBoost"), ("extra_trees", "Extra Trees"), ("random_forest", "Random Forest"),
         ("decision_tree", "Decision Tree"), ("lightgbm_balanced", "LightGBM*")]
rows = [["Model", "Macro-F1", "Binary F1", "FPR(%)"]]
for key, name in NAMES:
    x = m[key]
    rows.append([name, f"{x['macro_f1']:.3f}", f"{x['binary_f1']:.4f}", f"{x['false_positive_rate'] * 100:.2f}"])
sqli = {k: m[k]["per_class"]["Web Attack - Sql Injection"]["f1-score"] for k, _ in NAMES[:4]}
others = [v for k, v in sqli.items() if k != "xgboost"]
xg = m["xgboost"]
B = "[  ]"

d = {
    "best_ko": "XGBoost",
    "llm_model": "gpt-5.4-mini",
    "abstract": (
        "Security operations centers (SOCs) must handle large volumes of alerts, and alert fatigue delays the "
        "response to real threats. This paper proposes a SOC assistant alert bot that groups flow-level anomaly "
        "detection results into alerts by one-minute window and destination asset, scores each alert with the "
        "KISA risk model defined as the product of attack degree, impact, and asset value, and summarizes "
        "high-risk alerts with a large language model (LLM) that receives the scoring rationale as input. "
        "The bot differentiates its response into immediate notification, periodic reporting, and logging by "
        f"risk grade. On the CICIDS2017 dataset, XGBoost achieved the highest macro-F1 ({xg['macro_f1']:.3f}) "
        f"among five classifiers with a false positive rate of {xg['false_positive_rate'] * 100:.2f}% and was "
        "selected as the detector. [Risk prioritization results]."),
    "exp_setup": (
        "실험에는 CICIDS2017[7]의 GeneratedLabelledFlows 중 화~금요일 2,300,825개 flow를 사용하였다. "
        "목요일 오전 파일 끝의 빈 행 288,602줄은 제외하고, 깨진 레이블 문자와 12시간제로 기록된 오후 시각을 보정하였다. "
        "탐지 모델은 IP·포트·시각을 제외한 79개 특징으로 학습하고 5-fold 층화 교차 예측으로 모든 flow에 판정을 붙였다. "
        "모델 선정은 공격 flow 전부와 정상 flow 20%를 표본으로 한 같은 조건에서 5종을 비교하였으며, 충격도가 유형 판정에 "
        "의존하므로 드문 유형까지 고르게 반영하는 macro-F1을 기준으로 하였다(Table 2)."),
    "table_models": rows,
    "model_result": (
        f"XGBoost가 macro-F1 {xg['macro_f1']:.3f}, 오탐률(FPR) {xg['false_positive_rate'] * 100:.2f}%로 가장 우수하였고, "
        f"특히 표본이 21건인 SQL Injection의 F1이 {sqli['xgboost']:.3f}로 다른 모델({min(others):.3f}~{max(others):.3f})보다 높았다. "
        "이진 F1은 트리 기반 4종 모두 0.998 이상으로 차이가 작아, 모델 선택은 유형 구분 성능이 좌우하였다. "
        "*LightGBM은 학습률·클래스 가중치를 바꾼 두 설정 모두 학습이 수렴하지 않았다."),
    "exp_result": (
        f"공격도 경계는 화·수요일 데이터로 보정하고($b_1$={B}, $b_2$={B}) 목·금요일 데이터로 평가하였다. "
        "경보에 묶인 flow 중 실제 공격 비율이 0.5 이상인 경보를 참 경보로 정의하였다. "
        f"이상 flow {B}건은 경보 {B}건으로 묶였고(경보당 {B} flow), 즉시 알림(심각·경계)은 {B}건({B}%)이었으며 "
        f"즉시 알림 정밀도는 {B}였다."),
    "table_ablation": [["Ranking", "AUC", "Precision@k"]] + [[n, B, B] for n in
                       ["$T$", "$A$", "$T TIMES A$", "$T TIMES I$", "$T TIMES I TIMES A$ (proposed)"]],
    "exp_result2": (
        f"Table 3에서 [요소 조합 비교 결과]. 예측 유형 기반 위험도와 정답 유형 기반 위험도의 Spearman 상관은 {B}로 "
        f"[오분류 강건성 해석]. GPT 요약은 즉시 알림 {B}건에 대해 평균 {B}초가 걸렸다."),
    "conclusion": (
        "본 논문은 이상탐지 결과를 경보 단위로 묶어 KISA 위험도 모델로 우선순위를 정하고, 등급에 따라 LLM 요약과 알림을 "
        "차등 제공하는 SOC 업무 보조 알림봇을 제안하였다. CICIDS2017에서 5종 모델을 비교한 결과 XGBoost가 macro-F1 "
        f"{xg['macro_f1']:.3f}로 가장 우수하였으며, [위험도 산정 결과 요약]. 다만 $T$, $I$, $A$의 척도와 등급 경계는 전문가 "
        "판단에 기반하며 민감도 분석은 수행하지 않았다. 또한 flow를 무작위로 나누는 교차 예측은 같은 공격 세션이 학습과 "
        "판정에 함께 들어갈 수 있어 탐지 성능이 실제보다 높게 나올 수 있다. 향후 요일 단위 분리 평가와 실제 관제 로그 "
        "적용을 진행할 계획이다."),
}
out = Path(__file__).resolve().parent / "results.json"
out.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
print(json.dumps(rows, ensure_ascii=False), sqli)
