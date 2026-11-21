#!/usr/bin/env bash
# 논문 실험 재현: 선정 모델로 이상탐지 → 위험도 산정(화·수 보정, 목·금 평가) → GPT 요약·알림
# 사용: bash experiments/run_pipeline.sh <모델이름> [데이터 폴더]
#   OPENAI_API_KEY가 있으면 GPT 요약, 없으면 템플릿 요약. DISCORD_WEBHOOK_URL이 없으면 화면·파일로만 기록.
set -euo pipefail
MODEL="$1"
DATA="${2:-../data/cicids2017/TrafficLabelling}"
OUT=experiments/run_$MODEL

py -m kisa_scoring.detect --slim --model "$MODEL" --out-dir "$OUT/pred" --input \
  "$DATA"/Tuesday-*.csv "$DATA"/Wednesday-*.csv "$DATA"/Thursday-*.csv "$DATA"/Friday-*.csv

py -m kisa_scoring --pred "$OUT"/pred/Thursday-*.csv "$OUT"/pred/Friday-*.csv \
  --calib "$OUT"/pred/Tuesday-*.csv "$OUT"/pred/Wednesday-*.csv --true-col label --out "$OUT/results"

py -m kisa_scoring.alert_bot --alerts "$OUT/results/alerts.json" --out "$OUT/bot" --limit 10
