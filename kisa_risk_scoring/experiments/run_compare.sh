#!/usr/bin/env bash
# 모델마다 별도 프로세스로 실행해 메모리를 매번 반환한다. 이미 결과가 있는 모델은 건너뛴다.
cd "$(dirname "$0")/.."
for m in lightgbm xgboost extra_trees random_forest; do  # lightgbm = 안정화 설정
  if [ -f experiments/results/metrics_$m.json ]; then echo "skip $m"; continue; fi
  jobs=""; case $m in extra_trees|random_forest) jobs="--n-jobs 6";; esac
  py experiments/compare_models.py --data ../data/cicids2017/TrafficLabelling --out experiments/results --models $m $jobs || echo "FAILED $m"
done
