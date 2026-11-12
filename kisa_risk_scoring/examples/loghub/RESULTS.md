# LogHub 실제 서버 로그 검증 결과

실행일 2026-11-11 · 데이터 [logpai/loghub](https://github.com/logpai/loghub) (`OpenSSH/OpenSSH_2k.log`, `Linux/Linux_2k.log`)
· LLM `gpt-5.4-mini` (OpenAI) · 테스트 25개 통과

## 1. 무엇을 검증했나

논문 시스템(경보 생성 → KISA 위험도 → LLM 요약 → 알림)이 **실제 서버에 들어온 공격 로그**에서도 끝까지 동작하는지,
우선순위가 의도대로 매겨지는지, LLM 요약이 입력에 없는 사실을 만들지 않는지를 확인했다.

LogHub에는 **공격 정답 레이블이 없다.** 그래서
- LightGBM 학습은 할 수 없어, 이상탐지 단계는 sshd·ftpd 메시지 템플릿(시그니처) 판정으로 대신했다 (`kisa_scoring/loghub.py`).
- 정밀도·AUC·precision@k는 계산하지 않는다. 이 지표는 CICIDS2017로 평가한다(논문 표 3).

## 2. 데이터와 설정

| 로그 | 서버 | 기간 | 전체 줄 | 이상 판정 | 공격 출발지 IP |
|---|---|---|---|---|---|
| OpenSSH_2k | LabSZ | 2015-12-10 06:55 ~ 11:04 (약 4시간) | 2,008 | 626 (무차별 대입 531, 정찰 95) | 26개 |
| Linux_2k | combo | 2005-06-14 ~ 07-27 | 1,992 | 1,219 (FTP 접속 시도 909, SSH 무차별 대입 310) | 66개 |

- 판정 규칙: 로그인 실패 1회 = `SSH-BruteForce` 1건(같은 시도의 중복 줄은 제외), 역방향 DNS 불일치·식별 문자열 없음 = `SSH-Recon`,
  ftpd 접속 = `FTP-Probe`, 실패 5회 이상 뒤 로그인 성공 = `SSH-LoginAfterFailures`(이번 데이터에서는 0건).
- 충격도 I: 무차별 대입 2(CICIDS의 SSH-Patator와 같음), 정찰·FTP 접속 시도 1(PortScan과 같음), 실패 후 성공 3.
- 자산가치 A **[가정]**: LabSZ 3(외부에 SSH를 연 서버), combo 2. LogHub는 서버 IP를 공개하지 않아 문서용 대역 IP(192.0.2.10/.20)를 붙였다.
- 공격도 경계: 각 로그의 **앞 50%(시간순)로 보정**, 뒤 50%로 평가 → b1 = 6건, b2 = 23건 (분당 이상 이벤트 수).

## 3. 결과

### 3.1 경보 집약과 등급 분포 (평가 구간)

| 항목 | 값 |
|---|---|
| 이상 이벤트 | 1,023건 |
| 경보 수 | 59건 |
| **경보 집약률** (이상 이벤트 / 경보) | **17.3** |
| 등급 분포 | 심각 0 · 경계 12 · 주의 12 · 관심 35 |
| **즉시 알림 비율** (심각+경계) | **20.3%** (12 / 59) |

분석가가 이상 이벤트 1,023건을 하나씩 보는 대신, 즉시 확인할 경보 12건과 정기 보고 12건만 보면 된다.
나머지 35건은 기록으로 남는다.

### 3.2 우선순위가 의도대로 매겨졌나

| 관찰 | 의미 |
|---|---|
| combo의 FTP 접속 시도 경보 29건(분당 1~23건)은 **모두 관심 등급**(최대 T=2, I=1, A=2 → 4점) | 건수만으로 정렬하면 상위에 섞일 정찰성 접속이 충격도 I로 걸러졌다 |
| combo의 SSH 무차별 대입(분당 46건, 위험도 12)이 LabSZ의 무차별 대입(분당 27~31건, 위험도 18)보다 **아래** | 건수가 더 많아도 자산가치 A가 낮으면 뒤로 간다 |
| 즉시 알림 12건이 **모두 SSH 무차별 대입**이고, 11건이 A=3 서버(LabSZ) | 경보 1건 = 실제 대응이 필요한 공격 시간대 |
| 즉시 알림 구간(10:54~11:04)은 출발지 `183.62.140.253`의 연속 공격 | 같은 공격이 분 단위로 쪼개져 10건이 됨 → 출발지 기준 병합은 향후 과제 |

### 3.3 LLM 요약 (gpt-5.4-mini, 즉시 알림 12건)

| 항목 | 값 |
|---|---|
| 호출 수 | 12회 (실패·템플릿 대체 0회) |
| 응답 시간 | 평균 2.37초, 최대 5.65초 |
| 토큰 | 입력 평균 475, 출력 평균 174 |
| **사실 일치 검사 통과** | **12 / 12** — 입력에 없는 IP 0건, 틀린 T·I·A 값 0건, 틀린 건수 0건 |
| T·I·A 근거 인용 | 12 / 12 |

검사 방법: 요약문의 IP가 경보의 출발지·목적지 목록에 있는지, `T=`·`I=`·`A=` 값이 경보와 같은지,
"N건"이 경보의 이벤트 수와 같은지 자동으로 비교했다 (`examples/loghub/evaluate_loghub.py`).

실제 요약 예시 (위험도 18, 경계):
```
상황: 2015-12-10 11:00:00~11:00:59(KST), LabSZ(SSH 서버)에서 SSH-BruteForce 경보 31건
위험도 근거: T=3(1분 동안 이상 이벤트 31건), I=2(유형: SSH-BruteForce), A=3(LabSZ (SSH 서버))
권장 조치: 해당 SSH 접속 시도에 대한 계정 잠금/비밀번호 정책 점검, 출발지 IP(183.62.140.253, 88.147.143.242) 접근 차단 검토
```

관찰된 문제: 일부 요약이 이벤트 31건을 "경보 31건"으로 부르고, 시간대를 입력의 `Asia/Seoul`에서 "KST"로 바꿔 적었다.
숫자는 맞지만 용어가 섞이므로, 프롬프트에 "건수는 '이상 이벤트'로 부른다"를 넣는 것이 좋다.

## 4. 한계

- 정답 레이블이 없어 우선순위의 정확도(정밀도, AUC)는 평가하지 못했다.
- 이상탐지가 LightGBM이 아니라 템플릿 판정이다. 모델 성능은 CICIDS2017로 따로 평가해야 한다.
- 자산가치는 가정값이다. OpenSSH_2k는 약 4시간 분량이라 경보 수가 적다.

## 5. 논문 Ⅲ장에 넣을 문단 초안

> 제안 시스템이 실제 서버 로그에서도 동작하는지 확인하기 위해 LogHub[8]의 OpenSSH 및 Linux 로그(각 2,000줄)를 사용하였다.
> LogHub에는 공격 레이블이 없으므로 sshd·ftpd 메시지 템플릿으로 로그인 실패, 정찰, FTP 접속 시도를 판정하고,
> 각 로그의 앞 50%로 공격도 경계를 보정한 뒤 나머지 50%로 평가하였다. 평가 구간의 이상 이벤트 1,023건은
> 경보 59건으로 묶여 경보 집약률은 17.3이었고, 즉시 알림 대상(심각·경계)은 12건(20.3%)이었다.
> 분당 최대 23건의 FTP 접속 시도 경보는 충격도가 낮아 모두 관심 등급으로 분류된 반면, 즉시 알림 12건은
> 모두 SSH 무차별 대입 경보였다. 즉시 알림 경보를 gpt-5.4-mini로 요약한 결과 평균 응답 시간은 2.37초였으며,
> 요약문의 IP·위험도 요소 값·이벤트 수를 입력과 대조한 사실 일치 검사를 12건 모두 통과하였다.

참고문헌 추가: [8] J. Zhu, S. He, P. He, J. Liu, and M. R. Lyu, "Loghub: A large collection of system log datasets for AI-driven log analytics", Proc. IEEE ISSRE, 2023.

## 6. 재현

```bash
cd kisa_risk_scoring
python -m kisa_scoring.loghub --openssh ../data/loghub/OpenSSH_2k.log --linux ../data/loghub/Linux_2k.log --out-dir examples/loghub/events
python -m kisa_scoring --input-format generic --config config/loghub.yaml \
       --pred examples/loghub/events/eval.jsonl --calib examples/loghub/events/calib.jsonl --out examples/loghub/results
export OPENAI_API_KEY=...            # 없으면 템플릿 요약
python -m kisa_scoring.alert_bot --alerts examples/loghub/results/alerts.json --out examples/loghub/bot
python examples/loghub/evaluate_loghub.py
```
