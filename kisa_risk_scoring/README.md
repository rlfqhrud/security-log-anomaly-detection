# KISA 기반 SOC 경보 위험도 산정 모듈

보안 로그 이상탐지 + LLM 요약 기반 SOC 업무 보조 알림봇의 위험도 산정 단계.
이상탐지 모델이 **flow 단위**로 판정한 결과(CICIDS2017)를 **경보 단위**로 묶고,
`위험도 = 공격도(T) × 충격도(I) × 자산가치(A)`로 점수와 등급을 매긴다.

## 0. 전체 파이프라인 (논문 그림 1의 5단계)

| 단계 | 모듈 | 내용 |
|---|---|---|
| ① 로그 전처리 | `kisa_scoring/adapters/cicids2017.py` | 컬럼명·레이블·12시간제 Timestamp 정규화 |
| ② 이상탐지 | `kisa_scoring/detect.py` | **LightGBM** 다중 분류, 5-fold 교차 예측으로 flow마다 `pred` 부여 |
| ③ 경보 생성·위험도 산정 | `kisa_scoring/scoring.py` | (1분 창, 목적지 IP) 경보, R = T × I × A, 4등급 |
| ④ LLM 요약 | `kisa_scoring/llm_summary.py` | 심각·경계 경보의 점수 근거를 **OpenAI GPT**로 요약 (키 없으면 템플릿 요약) |
| ⑤ 알림 전달 | `kisa_scoring/alert_bot.py` | 심각·경계 → **Discord 웹훅** 즉시 알림, 주의 → 정기 보고서, 관심 → 기록 |

```bash
pip install -r requirements.txt

# ② 이상탐지: 모든 요일 CSV에 pred 컬럼을 붙여 pred/ 폴더에 저장 (+ detect_metrics.json, feature_importance.csv)
python -m kisa_scoring.detect --input Tuesday-*.csv Wednesday-*.csv Thursday-*.csv Friday-*.csv --out-dir pred

# ③ 위험도 산정: 화·수로 공격도 경계 보정, 목·금 평가
python -m kisa_scoring --pred pred/Thursday-*.csv pred/Friday-*.csv \
       --calib pred/Tuesday-*.csv pred/Wednesday-*.csv --true-col label --out results

# ④⑤ LLM 요약 + 알림봇
export OPENAI_API_KEY=sk-...                                   # 없으면 템플릿 요약
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... # 없으면 화면 출력
python -m kisa_scoring.alert_bot --alerts results/alerts.json --out results/bot --limit 10
```

- 모델은 `OPENAI_MODEL` 환경 변수 또는 `--model`로 바꾼다 (기본 `gpt-5.4-mini`, GPT-4 계열도 지원).
- `--limit`은 시연용 즉시 알림 상한이다. 넘친 경보는 보고서(`periodic_report.md`)로 간다.
- 왜 교차 예측인가: CICIDS2017은 요일마다 공격 유형이 달라 화·수로만 학습하면 목·금 유형을 모른다.
  flow를 무작위로 나누므로 같은 공격 세션이 학습·판정 양쪽에 들어가 탐지 성능이 실제보다 높게 나올 수 있다(논문 한계에 기재).
- 합성 데이터 시연: `python examples/make_synthetic.py` 후 위 명령의 입력을
  `examples/data/calib_tue_wed.csv`, `examples/data/eval_thu_fri.csv`로 바꾼다. 결과 예시는 `examples/pipeline/`.
  **합성 데이터 수치는 논문에 쓰지 않는다.**

### LogHub 실제 서버 로그 검증

GitHub [logpai/loghub](https://github.com/logpai/loghub)의 OpenSSH·Linux 로그로 경보 생성 → 위험도 → GPT 요약 → 알림을 검증했다.
결과와 재현 방법은 [`examples/loghub/RESULTS.md`](examples/loghub/RESULTS.md). 변환기는 `kisa_scoring/loghub.py`, 설정은 `config/loghub.yaml`.

## 1. 실행 방법

```bash
pip install -r requirements.txt

# 테스트 (10개)
python -m pytest -q

# 합성 데이터로 파이프라인 확인
python examples/make_synthetic.py
python -m kisa_scoring --pred examples/data/eval_thu_fri.csv \
       --calib examples/data/calib_tue_wed.csv --true-col label --out examples/results
```

CLI 옵션:

| 옵션 | 설명 |
|---|---|
| `--pred P.csv` | 평가(산정) 대상 flow CSV. 필수 |
| `--calib C.csv` | 공격도 경계를 학습할 보정 CSV |
| `--params params.json` | 저장된 공격도 경계를 재사용 (`--calib`과 함께 쓸 수 없음) |
| `--pred-col` | 모델 판정 컬럼 (기본 `pred`) |
| `--true-col` | 정답 컬럼. 주면 평가표와 그림을 만든다 (예: `label`) |
| `--mode binary\|multiclass` | 설정 파일의 mode 덮어쓰기 |
| `--no-fix-12h` | 12시간제 오후 시각 보정 끄기 |
| `--tp-ratio` | 참 경보 기준 (기본 0.5) |
| `--config` | 설정 YAML (기본 `config/default.yaml`) |
| `--out` | 출력 폴더 (기본 `results`) |

`--calib`과 `--params`가 모두 없으면 평가 데이터로 경계를 학습하고 stderr에 경고를 출력한다.
논문 실험에서는 반드시 보정 데이터를 분리한다.

파이썬에서 직접 쓰는 경우:

```python
from kisa_scoring import RiskScorer, ScoringConfig, load_cicids2017

cfg = ScoringConfig.from_yaml("config/default.yaml")
calib = load_cicids2017(["Tuesday-...pcap_ISCX.csv", "Wednesday-...pcap_ISCX.csv"])
evald = load_cicids2017(["Thursday-...csv", "Friday-...csv"])
# calib/evald에 모델 판정 컬럼 'pred'를 붙인 뒤
scorer = RiskScorer(cfg).fit(calib, pred_col="pred")
alerts = scorer.score(evald, pred_col="pred", true_col="label")
records = RiskScorer.to_alert_records(alerts, min_grade_score=12)   # 즉시 알림 대상만
```

## 2. 입력과 출력

### 입력
- **CICIDS2017 GeneratedLabelledFlows(TrafficLabelling) CSV** + 모델 판정 컬럼.
  MachineLearningCSV에는 Source/Destination IP와 Timestamp가 없어 경보를 만들 수 없으므로 오류를 낸다.
- 필요한 컬럼: `Destination IP`, `Timestamp`, 판정 컬럼. `Source IP`가 있으면 경보에 상위 출발지 5개를 기록한다.
- 판정 컬럼: multiclass 모드는 공격 유형 레이블(`BENIGN`, `DDoS` …), binary 모드는 bool·0/1·문자열(BENIGN이 아니면 이상).
- CSV는 `encoding="latin-1"`, `low_memory=False`로 읽고 컬럼명 앞 공백을 제거한다.

### 출력 (`--out` 폴더)

| 파일 | 내용 |
|---|---|
| `params.json` | 공격도 경계 (b1, b2), 학습 정보, window, mode |
| `alerts.csv` | 경보 전체 표 (utf-8-sig, 엑셀에서 바로 열림) |
| `alerts.json` | 알림봇·LLM 요약 입력용 레코드 (근거 문자열 `rationale` 포함) |
| `eval_by_grade.csv` | 등급별 경보 수·참/오경보·비중·정밀도 (`--true-col` 있을 때) |
| `eval_ablation.csv` | 정렬 기준별 AUC, precision@k |
| `eval_summary.json` | 요약 지표 |
| `fig_eval.png` | 평가 그림 (200dpi) |

## 3. 방법

### 3.1 경보 단위
이상으로 판정된 flow를 `(시간 창, 목적지 IP)`로 묶어 경보 1건으로 만든다.
창은 기본 1분이다(CICIDS2017 Timestamp가 분 단위로 기록된 파일이 있으므로 1분보다 작게 잡지 않는다).

### 3.2 공식
KISA 특허 KR100955281B1 「위협 관리를 위한 보안 위험도 평가 방법」의 구조를 따른다.

| mode | 공식 | 범위 |
|---|---|---|
| multiclass | R = T × I × A | 1~27 |
| binary (유형 정보 없음) | R = T × A | 1~9 |

### 3.3 요소 정의

**공격도 T** — 창 안 같은 목적지로 향한 이상 flow 건수 n

| T | 조건 |
|---|---|
| 1 | n ≤ b1 |
| 2 | b1 < n ≤ b2 |
| 3 | n > b2 |

b1, b2는 보정 데이터 경보들의 flow 건수 분포에서 50%, 90% 분위수로 학습한다(`method: quantile`).
고정값을 쓰려면 `method: fixed`, `thresholds: [b1, b2]`.

**충격도 I** — 공격 유형이 성공했을 때 피해의 크기

| I | 유형 | 근거 |
|---|---|---|
| 3 (상) | Heartbleed, Infiltration, Bot, Web Attack - Sql Injection | 정보 유출, 내부 침투, 원격 제어 |
| 2 (중) | DoS Hulk/GoldenEye/slowloris/Slowhttptest, DDoS, FTP-Patator, SSH-Patator, Web Attack - Brute Force/XSS | 가용성 침해, 계정 탈취 시도 |
| 1 (하) | PortScan | 정찰 단계 |
| 2 (기본) | 목록에 없는 유형 | |

한 경보에 여러 유형이 섞이면 **창 안 비중이 `min_share`(기본 5%) 이상인 유형 중 가장 심각한 유형**을 쓰고
(동률이면 비중이 큰 쪽), 그런 유형이 없으면 최다 유형을 쓴다.
순수 max를 쓰면 오분류 flow 1건이 경보 전체의 충격도를 3으로 올리기 때문이다.

**자산가치 A** — 목적지 IP 기준 (UNB CIC 공개 피해자 네트워크)

| A | 자산 |
|---|---|
| 3 | DC/DNS 192.168.10.3, 웹서버 192.168.10.50 (공인 205.174.165.68), Ubuntu12 서버 192.168.10.51 (공인 205.174.165.66) |
| 2 | 사용자 PC 192.168.10.19, .17, .16, .12, .9, .5, .8, .14, .15, .25 |
| 1 | 그 밖의 IP ("미등록 자산") |

### 3.4 등급표

| 등급 | multiclass | binary | 조치 |
|---|---|---|---|
| 심각 | R ≥ 27 | R ≥ 9 | 즉시 알림 + LLM 상세 요약 |
| 경계 | R ≥ 12 | R ≥ 6 | 즉시 알림 + LLM 요약 |
| 주의 | R ≥ 6 | R ≥ 3 | 정기 요약 보고에 포함 |
| 관심 | R ≥ 1 | R ≥ 1 | 기록 |

등급 명칭은 국가 사이버위기 경보 단계에서 이름만 빌렸으며 국가 경보 발령 기준과는 무관하다.

### 3.5 근거 문헌과 자체 수립 부분

| 구분 | 내용 |
|---|---|
| 문헌 근거 | 위험도 = 공격도 × 충격도 × 자산가치 구조 (KISA 특허 KR100955281B1) |
| 문헌 근거 | 위험 평가 기준·척도를 조직이 정의하고 문서화해야 한다는 요구 (KISA ISMS-P 인증기준 안내서(2022) 1.2.3) |
| 문헌 근거 | 자산 구성·공격 일정 (UNB CIC CICIDS2017 공개 자료) |
| **자체 수립** | 1~3 척도, 공격도 분위수(0.5, 0.9), 유형별 충격도, 자산 등급, min_share, 등급 경계와 조치 |

자체 수립 값은 모두 `config/default.yaml`에 주석과 함께 분리되어 있다.

## 4. 평가 지표

- **참 경보(TP)**: 경보에 묶인 flow 중 실제 공격 비율(`true_attack_ratio`)이 `--tp-ratio`(기본 0.5) 이상인 경보.
- **등급별**: 경보 수, 참/오경보, 비중, 정밀도.
- **요약**: 이상 flow 수, 경보 수, 경보당 flow 수(묶음 효과), 즉시 알림(심각+경계) 건수·비중, 전체·즉시 알림 정밀도.
- **정렬 기준 비교(ablation)**: T, A, T×A, T×I, T×I×A(제안)를 각각 순위 기준으로 썼을 때
  - 참/오경보 구분 AUC (한 클래스만 있으면 NaN)
  - precision@k (k = 즉시 알림 건수, 동점은 flow 수 → 시각 순)
- **충격도 타당성** (multiclass): 참 경보에서 정답 레이블로 계산한 위험도 `T × true_impact × A`와 예측 위험도의 Spearman 상관, 예측 I와 정답 I의 일치율.

> scikit-learn·scipy를 불러올 수 없는 환경(예: Windows 애플리케이션 제어가 DLL을 차단)에서는
> 같은 정의의 numpy 구현(AUC = Mann-Whitney U, Spearman = 순위의 Pearson 상관)으로 계산한다.

## 5. 실험 설계 권장

- **화·수 보정 / 목·금 평가**: 화(FTP/SSH-Patator)·수(DoS 4종, Heartbleed)로 공격도 경계를 학습하고,
  목(Web Attack 3종, Infiltration)·금(Bot, PortScan, DDoS)에 적용한다. 평가 데이터로 경계를 학습하면 결과가 낙관적으로 나온다.
- 월요일(정상만)은 오탐 수준 확인용으로 보정 데이터에 넣을 수 있다.
- 이상탐지 모델의 학습/평가 분할과 위험도 보정/평가 분할이 겹치지 않게 한다.

## 6. 데이터 이슈

- **레이블 인코딩**: 원본 Web Attack 레이블의 구분 문자가 cp1252 en dash(0x96)라
  UTF-8로 보면 `Web Attack � Brute Force`로 깨진다. `normalize_label()`이 `Web Attack - `로 통일한다.
- **12시간제**: 일부 파일은 오후 시각을 AM/PM 없이 기록한다(`6/7/2017 2:15` = 14:15).
  수집 시간이 09:00~17:00이므로 1~7시를 13~19시로 보정한다(`--no-fix-12h`로 끔). 날짜는 일/월/년 순서다.
- **NAT**: 공격 트래픽은 방화벽 NAT를 거쳐 기록되어 실제 데이터에서 출발지가 공격자 공인 IP(205.174.165.73)가 아니라
  내부 주소(172.16.0.1)로 보일 수 있고, 피해 서버도 공인/사설 IP 두 개로 나타날 수 있다.
  그래서 자산 목록에 공인 IP를 같은 등급으로 넣었다. 출발지 기준 분석에는 주의가 필요하다.

## 7. 한계

- 충격도·자산가치 척도와 등급 경계는 **전문가 판단(자체 수립)**이며 실증적으로 최적화된 값이 아니다.
- 분위수·min_share·등급 경계에 대한 **민감도 분석은 포함하지 않았다.**
- 자산가치는 **CICIDS2017 실험망 기준**이며 실제 조직에 적용하려면 자산 목록을 다시 작성해야 한다.
- KISA 특허의 **대응도(Pt, Pa)** 요소는 보안 장비·대응 현황 데이터가 없어 제외했다.
- `examples/make_synthetic.py`의 **합성 데이터 결과는 파이프라인 동작 확인용이며 논문 수치로 쓸 수 없다.**

## 8. 구조

```
kisa_risk_scoring/
├── config/default.yaml        # 척도·구간·등급 (근거 주석)
├── kisa_scoring/
│   ├── loader.py              # CSV 로드, 레이블·시각 정규화
│   ├── scoring.py             # ScoringConfig, RiskScorer
│   ├── evaluate.py            # 평가, 그림
│   └── cli.py                 # python -m kisa_scoring
├── tests/                     # pytest 10개
└── examples/make_synthetic.py # 합성 데이터
```
