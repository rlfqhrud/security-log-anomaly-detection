"""임계값 변경 전/후 등급별 인시던트(entity) 건수를 비교하는 스크립트.

기본적으로 현재 라이브 데모 로그(shared_logs.json, log_store 경유)를 쓴다.
다른 로그 묶음을 비교하고 싶으면 --logs로 JSON 파일(로그 리스트)을 지정한다.

주의: 5주차 3단계(임계값 스윕)로 나온 "검증된" 후보값이 아직 없다. 이
스크립트는 "이 임계값으로 바꾸면 등급 분포가 어떻게 바뀌는지"를 미리
계산해보는 용도지, 어떤 값이 옳다고 말해주지 않는다.
"""

import argparse
import json
from collections import Counter

import log_store
from risk_config import HIGH_THRESHOLD, MEDIUM_THRESHOLD, classify
from rules import run_all_rules


def score_entities(logs):
    """entity별 최종 점수만 계산 (scoring.RiskScorer와 동일한 누적 로직)."""
    hits = run_all_rules(logs)
    scores = {}
    for hit in hits:
        entity = hit["entity"]
        scores[entity] = min(1.0, scores.get(entity, 0.0) + hit["score"])
    return scores


def level_counts(scores, medium_threshold, high_threshold):
    counts = Counter()
    for score in scores.values():
        counts[classify(score, medium_threshold, high_threshold)] += 1
    return counts


def compare(logs, old_medium, old_high, new_medium, new_high):
    scores = score_entities(logs)
    before = level_counts(scores, old_medium, old_high)
    after = level_counts(scores, new_medium, new_high)
    return scores, before, after


def main():
    parser = argparse.ArgumentParser(description="위험 등급 임계값 변경 전/후 비교")
    parser.add_argument("--logs", help="비교할 로그 JSON 파일 (생략 시 라이브 데모 로그 사용)")
    parser.add_argument("--old-medium", type=float, default=MEDIUM_THRESHOLD)
    parser.add_argument("--old-high", type=float, default=HIGH_THRESHOLD)
    parser.add_argument("--new-medium", type=float, required=True)
    parser.add_argument("--new-high", type=float, required=True)
    args = parser.parse_args()

    if args.logs:
        with open(args.logs, "r", encoding="utf-8") as f:
            logs = json.load(f)
    else:
        logs = log_store.load_logs()

    scores, before, after = compare(
        logs, args.old_medium, args.old_high, args.new_medium, args.new_high
    )

    print(f"대상 entity 수: {len(scores)}건 (로그 {len(logs)}건 기준)")
    print(f"\n[변경 전] 중위험 임계값={args.old_medium}, 고위험 임계값={args.old_high}")
    for level in ("저위험", "중위험", "고위험"):
        print(f"  {level}: {before.get(level, 0)}건")

    print(f"\n[변경 후] 중위험 임계값={args.new_medium}, 고위험 임계값={args.new_high}")
    for level in ("저위험", "중위험", "고위험"):
        print(f"  {level}: {after.get(level, 0)}건")

    print("\n[차이]")
    for level in ("저위험", "중위험", "고위험"):
        diff = after.get(level, 0) - before.get(level, 0)
        sign = "+" if diff >= 0 else ""
        print(f"  {level}: {sign}{diff}")


if __name__ == "__main__":
    main()
