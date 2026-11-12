# 보안 로그 이상탐지 데모

> **논문 시스템(KISA 위험도 기반 경보 우선순위화 + LLM 요약 알림봇)은 [`kisa_risk_scoring/`](kisa_risk_scoring/README.md)에 있습니다.**
> LightGBM 이상탐지 → (1분 창, 목적지 IP) 경보 → R = T × I × A 4등급 → OpenAI GPT 요약 → Discord 알림의 5단계입니다.
> 이 폴더 최상위의 룰 기반 데모(0.3/0.5 3단계)는 웹 세션 실시간 시연용 이전 버전이며 논문 실험에는 쓰지 않습니다.

브루트포스 / 포트 스캔 / DoS(Flood·Slow) / 웹 공격(SQL 인젝션·XSS) 룰 기반
탐지와 위험도(Risk Score) 스코어링을 보여주는 로컬 데모입니다. 두 개의
서버로 구성됩니다.

**DoS는 두 가지로 나뉩니다** (`rules.py`):
- `DoS 공격(Flood)` — 짧은 시간에 폭주하는 요청 ("짧고 굵게", Hulk/GoldenEye류). 데모 사이트의 "⚡ 짧은 시간에 요청 25회" 버튼.
- `DoS 공격(Slow)` — 오래 끄는 저속 요청 ("길고 가늘게", slowloris류). "🐌 느리지만 꾸준히" 버튼.
- 한 세션이 Flood 조건을 이미 만족하면 Slow로 중복 집계하지 않습니다.
- CICIDS2017 플로우 통계 기반의 R-DOS-FLOOD/R-DOS-SLOW(`flow_rules.py`)는 이것과 **입력 신호가 다른 별개 구현**입니다 (세션 이벤트 타임스탬프 vs 네트워크 플로우 패킷 통계) — 서로의 검증 결과를 대신하지 않습니다.

- **대시보드** (`main.py`, 포트 8000): 로그를 분석해 위험도를 보여주는 보안 관제 화면
- **데모 사이트** (`target_site.py`, 포트 8001): 로그인/검색/접속/포트 접속 등 기본 기능만 있는 가짜 웹사이트.
  여기서 발생하는 활동은 `shared_logs.json`에 실시간으로 기록되고, 대시보드가 이를 읽어 분석합니다.

**개인정보 최소화**: 실명·이메일 등은 전혀 수집하지 않습니다. 방문자는 쿠키로 발급되는
임시 세션 식별자(`SESSION_XXXXXXXX`)로만 구분되며, 탐지·집계·알림은 이 세션 ID 기준으로
이루어집니다. 출발지 IP는 조사 참고용으로만 함께 표시됩니다. 정상/저위험 로그는 알림으로
보내지 않고 대시보드 하단의 "전체 로그 이력"에서만 조회할 수 있습니다 (`demo.py`는 세션 기반
구조 도입 전 사용하던 샘플 로그 생성기로, 현재는 사용하지 않습니다).

## 실행 방법

```
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
uvicorn target_site:app --reload --port 8001
```

두 명령을 각각 다른 터미널에서 실행한 뒤, 브라우저에서 데모 사이트(http://127.0.0.1:8001)에서
로그인/검색 등을 조작하고, 대시보드(http://127.0.0.1:8000)에서 "다시 스캔"을 눌러 탐지 결과를 확인하세요.

## 데이터 구성: CICIDS2017 vs LogHub (역할 분담)

이 프로젝트는 "정답 라벨이 있는 데이터"와 "정답 라벨이 없는 실제 공개 로그"를
용도를 분리해서 씁니다. 섞어 쓰지 않습니다.

| | CICIDS2017 (`analyze_logs.py`) | LogHub (`loghub_loader.py`) |
|---|---|---|
| 역할 | **성능 평가용** (precision/recall) | **룰 동작 검증용** (정답 라벨 없음) |
| 데이터 형태 | 79컬럼 플로우 통계 CSV (CICFlowMeter 가공) | OpenSSH/Apache 원본 서버 로그 |
| 현재 상태 | DRAFT: 아직 실제 CICIDS2017 CSV를 받지 못해 합성 데이터로만 스크립트 로직을 검증함 | `data/loghub/`에 LogHub 공식 샘플(OpenSSH_2k.log, Apache_2k.log)을 받아 실제로 돌려봄 |
| 결과 해석 | TP/FN/FP, precision/recall 계산 가능 (CICIDS2017 CSV 확보 후) | "몇 건 탐지했는지 + 근거 로그"만 리포트. **precision/recall 아님** |

```
# CICIDS2017 CSV 품질 분석 + 정제 (CSV 경로 필요)
python analyze_logs.py <csv경로> --out cleaned.csv

# LogHub 샘플로 룰 동작 검증 (저장소에 이미 포함된 샘플로 바로 실행 가능)
python loghub_loader.py
```

LogHub Apache 샘플은 access log가 아니라 error log라서 HTTP 요청/페이로드가
없습니다 — R-WEB-01(웹공격 시그니처)은 이 데이터로는 "신호가 있을 때 잡는지"를
검증할 수 없고 "신호 없을 때 오탐 안 하는지"만 확인됩니다. `loghub_loader.py`
실행 결과에 이 한계가 그대로 출력됩니다.

`flow_rules.py`는 CICIDS2017 DataFrame에 R-DOS-FLOOD/R-DOS-SLOW를 적용합니다
(임계값은 `flow_rule_config.yaml`, DRAFT). 같은 이유로 플로우 통계만으로는
R-WEB-01을 판단할 수 없어서, `web_attack_unavailable_notice()`가 "판단 불가"를
명시적으로 반환합니다 — 억지로 판정하지 않습니다.

```python
from analyze_logs import load_dataset, clean_dataset
from flow_rules import detect_dos_flood, detect_dos_slow

df = clean_dataset(load_dataset("<csv경로>"))
flood_hits = detect_dos_flood(df)
slow_hits = detect_dos_slow(df)
```

## 위험 등급 설정 방법

저위험/중위험/고위험 임계값과 참고 라벨(CVSS·KISA 경보단계 매핑)은
코드가 아니라 `risk_levels.yaml`에 있습니다. 값을 바꾸려면 이 파일만
수정하면 되고, 코드 재배포가 필요 없습니다.

```yaml
levels:
  medium:
    max_score: 0.3   # 이 값을 바꾸면 저위험/중위험 경계가 바뀜
  high:
    max_score: 0.5   # 중위험/고위험 경계 (이 설정에서는 사실상 medium의 다음 값)
```

**주의**: `reference.cvss`/`reference.kisa_alert`는 "참고용 대응표"일 뿐입니다.
Risk Score(0~1, 자체 가중합)는 CVSS나 KISA 경보단계와 산출 방식이 전혀
다르므로 숫자를 등치시키면 안 됩니다. 대시보드의 위험도 배지에 마우스를
올리면 이 설명이 툴팁으로 뜹니다.

임계값을 바꾸기 전에 영향도를 미리 확인하려면:

```
python compare_risk_thresholds.py --new-medium 0.2 --new-high 0.5
```

현재 라이브 데모 로그(`shared_logs.json`) 기준으로 변경 전/후 등급별
인시던트 건수를 비교해서 보여줍니다. `--logs <json경로>`로 다른 로그
묶음을 지정할 수도 있습니다 (예: LogHub 변환 결과).

**DRAFT**: 현재 0.3/0.5는 5주차 3단계에서 하기로 한 임계값 스윕(실데이터
기반 precision/recall/F1 비교)이 아직 실행되지 않아, 원래 설계값을 그대로
쓰고 있는 상태입니다. LogHub 실데이터로 확인한 결과, **브루트포스 단독
탐지(0.25점)는 현재 중위험 임계값(0.3)에도 못 미쳐 알림이 전혀 뜨지
않습니다** — 임계값 스윕 시 함께 재검토가 필요합니다.

## 룰 성능 평가 (TP/FN/FP, precision/recall, 임계값 스윕)

`evaluate_rules.py`가 평가 harness입니다. **실제 CICIDS2017 CSV가 있어야
진짜 수치가 나옵니다** — 없는 상태에서 돌리면 제가 만든 라벨을 제가
채점하는 셈이라 의미가 없습니다. CSV를 받으면:

```python
from analyze_logs import load_dataset, clean_dataset
from flow_rules import detect_dos_flood, load_config
from evaluate_rules import compute_confusion, class_recall, threshold_sweep, quantile_candidates, print_sweep_table

df = clean_dataset(load_dataset("<CICIDS2017 CSV 경로>"))

# TP/FN/FP, precision/recall/F1
print(compute_confusion(df, detect_dos_flood, positive_labels={"DoS Hulk", "DoS GoldenEye"}))

# 라벨별 recall (소수 클래스가 묻히지 않게)
print(class_recall(df, detect_dos_flood, positive_labels={"DoS Hulk", "DoS GoldenEye", "DoS slowloris"}))

# 분위수 기반 임계값 스윕
candidates = quantile_candidates(df, "Flow Packets/s")
rows = threshold_sweep(
    df, detect_dos_flood, load_config(),
    ("dos_flood", "min_flow_packets_per_sec"), candidates,
    positive_labels={"DoS Hulk", "DoS GoldenEye"},
)
print_sweep_table(rows)
```

**지금 당장 실제 데이터로 확인한 것**: "21/22/80 포트 조건이 정상 트래픽을
얼마나 잡는가"를 요청하셨는데, 포트 21(FTP)/80(access log) 쪽은 실제
정상 트래픽 데이터가 없어 확인 불가능합니다. 포트 22(SSH)는 LogHub 실제
로그로 확인했습니다:

- 전체 고유 출발지 IP 24개 중 11개(45.8%)가 브루트포스로 플래그됨
- 로그 전체에서 로그인에 **성공**한 IP는 1개(`119.137.62.142`)뿐이고,
  이 IP는 플래그된 11개와 **겹치지 않음** (플래그된 IP가 나중에 정상
  로그인에 성공한 사례 0건 — 이 각도에서는 명백한 오탐 신호 없음)
- 다만 이 데이터셋(LogHub OpenSSH_2k)은 원래 공개된 공격 대상 서버의
  로그로 알려져 있어, 45.8%라는 높은 비율이 "룰이 과민하다"는 뜻인지
  "이 서버가 실제로 그 정도로 공격받았다"는 뜻인지는 정답 라벨 없이는
  구분할 수 없습니다 — 한계로 남겨둡니다.

## 벤치마크 실행 방법

```
python benchmark_env.py                        # 기본: 1만/10만/100만 건
python benchmark_env.py --sizes 1000 50000      # 건수 직접 지정
```

실행 환경(OS/Python 버전/CPU 코어 수/RAM)과, 합성 로그 N건에 대한
로드→룰→스코어링 각 단계 처리 시간 + 피크 메모리 증가량을 표로 출력합니다.
**LLM 리포트 생성 구간은 현재 코드베이스에 구현되어 있지 않아 측정하지
않습니다** (추정치를 기재하지 않음 — LLM 연동이 추가되면 이 스크립트에
호출 횟수/평균 응답시간 측정을 추가해야 합니다).
