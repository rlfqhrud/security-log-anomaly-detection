"""CICIDS2017 플로우 CSV(MachineLearningCVE / TrafficLabelling) 품질 분석 및 정제.

CICIDS2017 CSV는 다음과 같은 알려진 문제가 있다:
- 컬럼명 앞뒤에 공백이 섞여 있다 (예: " Destination Port").
- Label 값에 인코딩이 깨진 문자(예: "Web Attack � XSS")가 섞여 있다.
- UTF-8로 읽히지 않는 파일이 있다 (TrafficLabelling 쪽에서 종종 발생).
- Flow Bytes/s, Flow Packets/s 등에 inf/NaN이 나올 수 있다 (Flow Duration이 0일 때).
- Init_Win_bytes_forward/backward의 -1은 "값 없음"을 뜻하는 정상 센티널이지,
  이상치가 아니다. 따라서 음수값 점검에서 이 두 컬럼은 제외한다.

이 스크립트는 (1) 원본 품질을 보고하고 (2) 정제된 DataFrame을 반환하는
두 단계로 나뉘며, 정제는 항상 "품질 리포트를 본 뒤" 수행한다.

DRAFT: 아직 실제 CICIDS2017 파일로 검증되지 않았다. 79컬럼 스키마를 기준으로
작성했고, tests/fixtures/synthetic_cicids_sample.csv (합성 데이터)로만
기계적 동작을 확인한 상태다.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Init_Win_bytes_forward/backward의 -1은 CICFlowMeter가 "관측 안 됨"을 뜻하는
# 정상 센티널 값이다. 음수값 품질 점검/정제 대상에서 제외한다.
NEGATIVE_CHECK_EXCLUDE_SUBSTR = "init_win_bytes"

# CICIDS2017 Label 값에서 관찰되는 깨진 구분자 문자들을 "-"로 정규화한다.
_BROKEN_DASH_CHARS = ["�", "�", "\x96", "\x97"]


def load_dataset(path):
    """CSV를 읽고 컬럼명 공백 제거 + Label 정규화까지 수행한다.
    utf-8로 읽기 실패하면 latin-1로 재시도한다."""
    path = Path(path)
    try:
        df = pd.read_csv(path, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)

    df.columns = [c.strip() for c in df.columns]

    label_col = _find_label_column(df)
    if label_col:
        df[label_col] = df[label_col].apply(_normalize_label)

    return df


def _find_label_column(df):
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    return None


def _normalize_label(value):
    if not isinstance(value, str):
        return value
    text = value.strip()
    for broken in _BROKEN_DASH_CHARS:
        text = text.replace(broken, "-")
    # 깨진 문자 치환 후 중복 공백 정리 (예: "Web Attack  - XSS" -> "Web Attack - XSS")
    return " ".join(text.split())


def _is_excluded_from_negative_check(col_name):
    return NEGATIVE_CHECK_EXCLUDE_SUBSTR in col_name.strip().lower()


def quality_report(df):
    """정제 전 데이터 품질을 점검해 dict로 반환한다. (출력은 print_quality_report가 담당)"""
    label_col = _find_label_column(df)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    report = {
        "n_rows": len(df),
        "n_cols": len(df.columns),
        "label_column": label_col,
        "label_distribution": df[label_col].value_counts().to_dict() if label_col else {},
    }

    # 라벨별 중복 행 수
    dup_mask = df.duplicated(keep=False)
    if label_col:
        report["duplicate_rows_by_label"] = (
            df.loc[dup_mask, label_col].value_counts().to_dict()
        )
    report["duplicate_rows_total"] = int(dup_mask.sum())

    # inf / NaN 컬럼
    inf_counts = {}
    nan_counts = {}
    negative_counts = {}
    constant_cols = []

    for col in numeric_cols:
        series = df[col]
        n_inf = int(np.isinf(series).sum())
        if n_inf:
            inf_counts[col] = n_inf
        n_nan = int(series.isna().sum())
        if n_nan:
            nan_counts[col] = n_nan
        if not _is_excluded_from_negative_check(col):
            n_neg = int((series < 0).sum())
            if n_neg:
                negative_counts[col] = n_neg
        if series.nunique(dropna=True) <= 1:
            constant_cols.append(col)

    report["inf_columns"] = inf_counts
    report["nan_columns"] = nan_counts
    report["negative_value_columns"] = negative_counts
    report["constant_columns"] = constant_cols

    return report


def print_quality_report(report):
    print(f"행 수: {report['n_rows']} / 컬럼 수: {report['n_cols']}")
    print(f"Label 컬럼: {report['label_column']}")
    print("\n[라벨 분포]")
    for label, count in report["label_distribution"].items():
        print(f"  {label}: {count}")

    print(f"\n[중복 행] 전체 {report['duplicate_rows_total']}건")
    for label, count in report.get("duplicate_rows_by_label", {}).items():
        print(f"  {label}: {count}")

    print("\n[inf 포함 컬럼]")
    if report["inf_columns"]:
        for col, count in report["inf_columns"].items():
            print(f"  {col}: {count}건")
    else:
        print("  없음")

    print("\n[NaN 포함 컬럼]")
    if report["nan_columns"]:
        for col, count in report["nan_columns"].items():
            print(f"  {col}: {count}건")
    else:
        print("  없음")

    print("\n[음수값 포함 컬럼] (Init_Win_bytes_* 제외)")
    if report["negative_value_columns"]:
        for col, count in report["negative_value_columns"].items():
            print(f"  {col}: {count}건")
    else:
        print("  없음")

    print("\n[상수 컬럼] (값이 1종류뿐)")
    if report["constant_columns"]:
        for col in report["constant_columns"]:
            print(f"  {col}")
    else:
        print("  없음")


def clean_dataset(df):
    """중복 제거 -> inf를 NaN으로 -> 음수를 NaN으로(Init_Win_bytes_* 제외) 순서로 정제한다."""
    before = len(df)
    cleaned = df.drop_duplicates().copy()
    after_dedup = len(cleaned)

    numeric_cols = cleaned.select_dtypes(include=[np.number]).columns.tolist()
    cleaned[numeric_cols] = cleaned[numeric_cols].replace([np.inf, -np.inf], np.nan)

    for col in numeric_cols:
        if _is_excluded_from_negative_check(col):
            continue
        cleaned.loc[cleaned[col] < 0, col] = np.nan

    after = len(cleaned)
    print(f"\n[정제 전후 비교] 원본 {before}행 -> 중복 제거 후 {after_dedup}행 -> 최종 {after}행")
    return cleaned


def main():
    parser = argparse.ArgumentParser(description="CICIDS2017 CSV 품질 분석 및 정제")
    parser.add_argument("path", help="CSV 파일 경로")
    parser.add_argument("--out", help="정제된 CSV를 저장할 경로 (생략 시 저장하지 않음)")
    args = parser.parse_args()

    df = load_dataset(args.path)
    report = quality_report(df)
    print_quality_report(report)

    cleaned = clean_dataset(df)

    if args.out:
        cleaned.to_csv(args.out, index=False)
        print(f"\n정제된 데이터를 저장했습니다: {args.out}")


if __name__ == "__main__":
    main()
