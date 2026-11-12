"""파이프라인(로드 -> 룰 -> 스코어링) 처리 성능을 실측하는 벤치마크 스크립트.

발표 슬라이드의 "일반 PC 1대에서 돌아간다"는 주장을 검증하기 위한 실측
도구다. 측정되지 않은 값은 추정해서 채우지 않는다.

중요한 한계: 이 프로젝트는 현재 LLM 리포트 생성 기능이 전혀 구현되어
있지 않다 (코드베이스 어디에도 외부 LLM API 호출이 없음). "LLM 포함/제외
시간 분리"는 LLM 연동이 구현된 뒤에만 측정 가능하므로, 이 스크립트는 그
구간을 "미구현 - 측정 불가"로 명시하고 절대 숫자를 꾸며내지 않는다.

로그 데이터는 실측 성능(처리 속도/메모리)만 보기 위한 합성 데이터다.
탐지 정확도를 보려는 게 아니므로 CICIDS2017/LogHub와는 목적이 다르다.
"""

import json
import os
import platform
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import psutil

from rules import run_all_rules
from scoring import RiskScorer

TMP_LOG_PATH = Path(__file__).resolve().parent / "_benchmark_tmp_logs.json"


def env_info():
    vm = psutil.virtual_memory()
    return {
        "os": platform.platform(),
        "python_version": sys.version.split()[0],
        "cpu_logical_cores": psutil.cpu_count(logical=True),
        "cpu_physical_cores": psutil.cpu_count(logical=False),
        "total_ram_gb": round(vm.total / (1024 ** 3), 2),
    }


def _generate_synthetic_logs(n, attack_session_ratio=0.02, seed=42):
    """성능 측정용 합성 로그 n건을 생성한다 (정확도 평가용 아님).
    세션의 attack_session_ratio만큼은 브루트포스 패턴(짧은 시간 내 로그인
    실패 반복)을, 나머지는 평범한 단발성 요청을 만든다."""
    rng = random.Random(seed)
    base_time = datetime(2026, 1, 1, 0, 0, 0)
    logs = []
    n_sessions = max(1, n // 20)  # 세션당 평균 20개 이벤트 정도

    t = base_time
    session_idx = 0
    while len(logs) < n:
        session_idx += 1
        session_id = f"SESSION_{session_idx:08d}"
        src_ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}"
        is_attack = rng.random() < attack_session_ratio

        if is_attack:
            for i in range(rng.randint(5, 8)):
                logs.append({
                    "timestamp": (t + timedelta(seconds=i * 2)).isoformat(),
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "event_type": "auth",
                    "status": "fail",
                })
        else:
            for i in range(rng.randint(1, 5)):
                logs.append({
                    "timestamp": (t + timedelta(seconds=i * 3)).isoformat(),
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "event_type": "http_request",
                    "path": "/home",
                    "query": "",
                    "status": 200,
                })
        t += timedelta(seconds=rng.randint(1, 5))

    return logs[:n]


def _peak_rss_mb(proc):
    return proc.memory_info().rss / (1024 ** 2)


def benchmark_one(n):
    proc = psutil.Process(os.getpid())

    # --- 합성 로그를 파일로 써서 "로드" 단계가 실제 파일 I/O + JSON 파싱을
    #     포함하도록 한다 (메모리에 이미 있는 리스트를 쓰는 건 눈속임이므로) ---
    logs_in_memory = _generate_synthetic_logs(n)
    with open(TMP_LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(logs_in_memory, f)
    del logs_in_memory

    rss_before = _peak_rss_mb(proc)

    t0 = time.perf_counter()
    with open(TMP_LOG_PATH, "r", encoding="utf-8") as f:
        logs = json.load(f)
    t1 = time.perf_counter()

    hits = run_all_rules(logs)
    t2 = time.perf_counter()

    scorer = RiskScorer()
    scorer.add_hits(hits)
    _ = scorer.incidents()
    t3 = time.perf_counter()

    rss_after = _peak_rss_mb(proc)

    return {
        "n": n,
        "actual_rows": len(logs),
        "load_s": round(t1 - t0, 3),
        "rules_s": round(t2 - t1, 3),
        "scoring_s": round(t3 - t2, 3),
        "total_pipeline_s": round(t3 - t0, 3),
        "rss_before_mb": round(rss_before, 1),
        "rss_after_mb": round(rss_after, 1),
        "rss_delta_mb": round(rss_after - rss_before, 1),
    }


def print_report(results, info):
    print("=" * 70)
    print("벤치마크 실행 환경 (실측)")
    print("=" * 70)
    for k, v in info.items():
        print(f"  {k}: {v}")

    print("\n[파이프라인 처리 성능 - 로드 -> 룰 -> 스코어링]")
    header = f"{'N':>10} | {'로드(s)':>9} | {'룰(s)':>9} | {'스코어링(s)':>11} | {'합계(s)':>9} | {'RSS 증가(MB)':>12}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['n']:>10} | {r['load_s']:>9} | {r['rules_s']:>9} | "
            f"{r['scoring_s']:>11} | {r['total_pipeline_s']:>9} | {r['rss_delta_mb']:>12}"
        )

    print(
        "\n[LLM 리포트 생성 구간]\n"
        "  미구현 - 측정 불가. 현재 코드베이스(rules.py/scoring.py/main.py 등)에는\n"
        "  외부 LLM API 호출이 전혀 없다. LLM 연동이 추가되면 호출 횟수와 평균\n"
        "  응답시간을 이 스크립트에 추가로 기록할 것."
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(description="파이프라인 성능 벤치마크")
    parser.add_argument(
        "--sizes", type=int, nargs="+", default=[10_000, 100_000, 1_000_000],
        help="측정할 로그 건수 목록",
    )
    args = parser.parse_args()

    info = env_info()
    results = [benchmark_one(n) for n in args.sizes]
    print_report(results, info)

    TMP_LOG_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
