"""논문 내용 (KICSP 양식). 수치는 experiments/ 결과 파일에서 옮긴다. $...$ 는 한글 수식 스크립트."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = json.loads((HERE / "results.json").read_text(encoding="utf-8")) if (HERE / "results.json").exists() else {}


def r(key, default="XX"):
    return RES.get(key, default)


TITLE_KO = "KISA 위험도 평가 기반 경보 우선순위화와 LLM 요약을 결합한 SOC 업무 보조 알림봇"
AUTHORS_KO = "길보경^1, 박여경^1, 이지연^1*"
AFFIL_KO = "^1한라대학교 AI정보보안학과"
TITLE_EN = "A SOC Assistant Alert Bot Combining KISA Risk Assessment-based Alert Prioritization and LLM Summarization"
AUTHORS_EN = "Bo-Gyeong Gil^1, Yeo-Gyeong Park^1, Ji-Yeon Lee^1*"
AFFIL_EN = "^1Dept. of AI Information Security, Halla University"
KEYWORDS = ("Security Operations Center, Alert Prioritization, Risk Assessment, Large Language Model, "
            "Anomaly Detection, CICIDS2017")

ABSTRACT = r("abstract", "XX")

BODY = [
    ("h1", "Ⅰ", "서론"),
    ("p", "보안관제센터(SOC)는 방화벽, 침입탐지시스템, 서버의 보안 로그를 분석해 위협에 대응하지만, "
          "경보의 양이 분석 인력의 처리 능력을 넘어서면서 대부분의 경보가 오탐으로 처리되는 경보 피로(alert fatigue)가 "
          "실제 위협의 누락과 대응 지연으로 이어지고 있다[1]. 머신러닝 이상탐지는 분석 대상을 줄일 수 있으나[2], "
          "판정이 flow 단위 레이블로만 제공되면 분석가는 여전히 많은 판정을 직접 묶고 우선순위를 정해야 한다. "
          "한국인터넷진흥원(KISA)의 보안 위험도 평가 방법은 위험도를 공격도, 충격도, 자산가치의 곱으로 정의하며[3], "
          "ISMS-P 인증기준은 위험도 산정 기준을 조직이 자체 수립하도록 한다[4]. 대규모 언어 모델(LLM)은 로그 해석 등 "
          "보안 분야 활용이 활발히 연구되고 있다[5]."),
    ("p", "본 논문은 이상탐지 결과를 (시간 창, 목적지 자산) 단위 경보로 묶어 KISA 위험도로 우선순위를 정하고, "
          "등급에 따라 LLM 요약과 알림을 차등 제공하는 SOC 업무 보조 알림봇을 제안한다. 또한 이상탐지 모델 5종을 "
          "비교해 탐지 모델을 선정하고, 요소 기여도 분석으로 각 위험도 요소의 효과를 평가한다."),

    ("h1", "Ⅱ", "제안 시스템"),
    ("h2", "2.1 시스템 구성"),
    ("p", "제안 시스템은 Fig. 1과 같이 로그 전처리, 이상탐지, 경보 생성 및 위험도 산정, LLM 요약, 알림 전달의 "
          "다섯 단계로 구성된다. 이상탐지 단계에서는 " + r("best_ko") + "가 각 flow를 정상 또는 14개 공격 유형으로 판정한다."),
    ("fig", 1),
    ("figcap", "Fig. 1 Architecture of the proposed system"),
    ("h2", "2.2 경보 생성과 위험도 산정"),
    ("p", "이상으로 판정된 flow를 목적지 IP $i$와 1분 시간 창 $w$로 묶어 하나의 경보로 만들고, 위험도 $R$을 "
          "KISA 방법[3]에 따라 식 (1)로 산정한다."),
    ("eq", "R(i,w)=T(i,w) TIMES I(i,w) TIMES A(i)", 1),
    ("p", "Table 1은 위험도 요소별 점수 기준이다. 공격도 $T$는 창 안의 이상 flow 수 $n(i,w)$를 보정 데이터 분포의 50%, 90% 분위수 경계 $b_1$, $b_2$로 "
          "3단계화한다. 충격도 $I$는 공격 유형이 침해하는 보안 속성과 공격 단계로 부여하였으며[6], 여러 유형이 섞이면 "
          "창 안 비중이 5% 이상인 유형 중 최고 심각도를 써서 오분류 flow 한 건이 경보 전체의 충격도를 높이지 않게 하였다. "
          "자산가치 $A$는 UNB가 공개한 실험망 구성[7]으로 부여하였다."),
    ("tabcap", "Table 1. Scoring criteria for each risk factor"),
    ("table", [
        ["Factor", "3", "2", "1"],
        ["T (attack)", "$n > b_2$", "$b_1 < n <= b_2$", "$n <= b_1$"],
        ["I (impact)", "Heartbleed, Infiltration,\nBot, SQL Injection", "DoS, DDoS, Patator,\nWeb Brute Force, XSS", "PortScan"],
        ["A (asset)", "Servers", "User PCs", "Others"],
    ], [1.1, 1.7, 1.7, 1.0]),
    ("h2", "2.3 등급별 대응과 LLM 요약"),
    ("p", "위험도는 심각($R=27$), 경계($12 <= R <= 18$), 주의($6 <= R <= 9$), 관심($R <= 4$)의 4등급으로 나눈다. "
          "등급 명칭은 국가 사이버위기 경보 단계에서 이름만 빌렸다. 심각·경계 경보는 각 요소의 점수 근거 문장을 포함한 "
          "JSON 레코드를 OpenAI GPT(" + r("llm_model") + ")에 전달하고, 생성된 요약문을 Discord 웹훅으로 즉시 전송한다. "
          "주의 등급은 정기 보고서에 포함하고 관심 등급은 기록만 남긴다."),

    ("h1", "Ⅲ", "실험 및 결과"),
    ("h2", "3.1 실험 환경"),
    ("p", r("exp_setup")),
    ("tabcap", "Table 2. Comparison of anomaly detection models"),
    ("table", r("table_models", [["Model", "Macro-F1", "Binary F1", "FPR(%)"]]), [1.6, 1.0, 1.0, 1.0]),
    ("p", r("model_result")),
    ("h2", "3.2 위험도 산정 결과"),
    ("p", r("exp_result")),
    ("tabcap", "Table 3. Alert prioritization by risk factor combination"),
    ("table", r("table_ablation", [["Ranking", "AUC", "Precision@k"]]), [1.4, 1.0, 1.0]),
    ("p", r("exp_result2")),

    ("h1", "Ⅳ", "결론"),
    ("p", r("conclusion")),

    ("ack_title",),
    ("ack", "본 과제(결과물)는 2026년도 교육부 및 강원특별자치도의 재원으로 강원앵커센터의 지원을 받아 수행된 "
            "지역성장 인재양성체계(앵커)의 결과입니다.(2026-ANCHOR-10-008)"),
    ("ref_title",),
    ("ref", "[1] B. A. Alahmadi, L. Axon, and I. Martinovic, \"99% false positives: A qualitative study of SOC analysts' "
            "perspectives on security alarms,\" Proc. 31st USENIX Security Symp., pp. 2783-2800, 2022."),
    ("ref", "[2] V. Chandola, A. Banerjee, and V. Kumar, \"Anomaly detection: A survey,\" ACM Computing Surveys, "
            "vol. 41, no. 3, pp. 1-58, 2009."),
    ("ref", "[3] P. Kang, W. Shim, and W. Kim, \"Security risk assessment method for threat management,\" "
            "Korean Patent 10-0955281, 2010."),
    ("ref", "[4] Korea Internet & Security Agency, ISMS-P Certification Criteria Guide, 2022."),
    ("ref", "[5] H. Xu et al., \"Large language models for cyber security: A systematic literature review,\" "
            "arXiv:2405.04760, 2024."),
    ("ref", "[6] Korea Internet & Security Agency, Detailed Guide to Technical Vulnerability Analysis and Evaluation "
            "of Critical Information Infrastructure, 2021."),
    ("ref", "[7] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, \"Toward generating a new intrusion detection "
            "dataset and intrusion traffic characterization,\" Proc. ICISSP, pp. 108-116, 2018."),
]
