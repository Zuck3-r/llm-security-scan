#!/usr/bin/env python3
"""Eval harness (CLAUDE.md §9 Step 2).

`evals/cases/*.diff` を `engine.scan_diff()` に流し、`evals/expected.yml` の
期待 verdict / perspective / 最低 confidence と突合する。

LLM は temperature=0 でも完全には決定的ではないので、不一致 case は
1 回だけ retry する（Run 1 fail → Run 2 pass なら PASS_RETRY 扱い）。
2 連続不一致なら本物の degrade として FAIL する。

判定セマンティクス:
  expect_verdict=confirmed
    該当観点に triage_status=confirmed の finding が 1 件以上存在し、
    最高 confidence が expect_min_confidence 以上であること。
  expect_verdict=dismissed
    該当観点に triage_status=confirmed の finding が 1 件も無いこと。
    （validator のゲートで弾かれた / LLM が検出しなかった / triage が
     dismissed 化したのいずれも OK）
  expect_verdict=inconclusive
    該当観点に triage_status=inconclusive の finding が 1 件以上。

使い方:
    python eval.py
    python eval.py --no-retry --verbose          # 1 回で fail (デバッグ)
    python eval.py --context SECURITY-CONTEXT.md # 文脈ありで eval
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # type: ignore

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))

from engine import scan_diff, load_context_file  # noqa: E402


# ── 期待値スキーマ ────────────────────────────────────────────
@dataclass
class Expected:
    case:           str
    verdict:        str       # "confirmed" | "dismissed" | "inconclusive"
    perspective:    str
    min_confidence: float = 0.0  # confirmed のみ意味あり


def load_expected(path: Path) -> list[Expected]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out: list[Expected] = []
    for entry in raw:
        out.append(Expected(
            case           = str(entry["case"]),
            verdict        = str(entry["expect_verdict"]).lower(),
            perspective    = str(entry["expect_perspective"]),
            min_confidence = float(entry.get("expect_min_confidence", 0.0)),
        ))
    return out


# ── case の判定 ───────────────────────────────────────────────
def _findings_for(ctx, perspective: str) -> list:
    for r in ctx.results:
        if r.perspective_id == perspective:
            return r.findings
    return []


def check_case(ctx, exp: Expected) -> tuple[bool, str, str]:
    """Returns (matched, actual_summary, reason_if_failed)."""
    findings = _findings_for(ctx, exp.perspective)
    confirmed    = [f for f in findings if f.triage_status == "confirmed"]
    dismissed    = [f for f in findings if f.triage_status == "dismissed"]
    inconclusive = [f for f in findings if f.triage_status == "inconclusive"]

    actual = (
        f"C={len(confirmed)} D={len(dismissed)} "
        f"I={len(inconclusive)} (total={len(findings)})"
    )

    if exp.verdict == "confirmed":
        if not confirmed:
            return False, actual, (
                f"expected >=1 confirmed in perspective={exp.perspective}, "
                f"got 0 (total findings={len(findings)})"
            )
        max_conf = max(f.triage_confidence for f in confirmed)
        if max_conf < exp.min_confidence:
            return False, actual, (
                f"max confidence {max_conf:.2f} < expected min {exp.min_confidence:.2f} "
                f"(titles={[f.title for f in confirmed[:3]]})"
            )
        return True, actual, ""

    if exp.verdict == "dismissed":
        if confirmed:
            return False, actual, (
                f"expected no confirmed in perspective={exp.perspective}, "
                f"got {len(confirmed)} (titles={[f.title for f in confirmed[:3]]})"
            )
        return True, actual, ""

    if exp.verdict == "inconclusive":
        if not inconclusive:
            return False, actual, (
                f"expected >=1 inconclusive in perspective={exp.perspective}, got 0"
            )
        return True, actual, ""

    return False, actual, f"unknown expected verdict: {exp.verdict!r}"


# ── 1 ケースの実行 (retry あり) ───────────────────────────────
@dataclass
class CaseResult:
    case:        str
    expected:    str
    actual:      str
    ok:          bool
    attempts:    int
    used_retry:  bool
    reason:      str        = ""
    error:       str        = ""


async def run_case(
    exp:              Expected,
    diff_path:        Path,
    perspectives_dir: Path,
    *,
    retry:            bool,
    context_text:     str   = "",
    verbose:          bool  = False,
    debate_rounds:    int   = 1,
) -> CaseResult:
    diff_text = diff_path.read_text(encoding="utf-8")
    expected_summary = f"{exp.verdict}/{exp.perspective}"
    if exp.verdict == "confirmed":
        expected_summary += f"/conf>={exp.min_confidence}"

    max_attempts = 2 if retry else 1
    last_actual = "?"
    last_reason = ""
    final_ok    = False

    for n in range(1, max_attempts + 1):
        try:
            ctx = await scan_diff(
                diff_text,
                perspectives_dir,
                enable_triage = True,
                context_text  = context_text,
                debate_rounds = debate_rounds,
            )
        except Exception as e:
            return CaseResult(
                case=exp.case, expected=expected_summary, actual="ERROR",
                ok=False, attempts=n, used_retry=False,
                reason="", error=f"{type(e).__name__}: {e}",
            )

        ok, actual, reason = check_case(ctx, exp)
        last_actual, last_reason, final_ok = actual, reason, ok

        if verbose:
            mark = "OK" if ok else "NG"
            print(f"  [{exp.case}] attempt {n}/{max_attempts}: {mark} actual={actual}",
                  file=sys.stderr)
            if not ok:
                print(f"    reason: {reason}", file=sys.stderr)

        if ok:
            return CaseResult(
                case=exp.case, expected=expected_summary, actual=actual,
                ok=True, attempts=n, used_retry=(n > 1),
            )
    # 2 連続失敗
    return CaseResult(
        case=exp.case, expected=expected_summary, actual=last_actual,
        ok=False, attempts=max_attempts, used_retry=False,
        reason=last_reason,
    )


# ── レポート ─────────────────────────────────────────────────
def _print_report(results: list[CaseResult]) -> None:
    # 列幅は実データに合わせる
    w_case     = max(4,  *(len(r.case)     for r in results))
    w_expected = max(8,  *(len(r.expected) for r in results))
    w_actual   = max(6,  *(len(r.actual)   for r in results))

    header = (
        f"{'case':<{w_case}}  "
        f"{'expected':<{w_expected}}  "
        f"{'actual':<{w_actual}}  "
        f"{'att':>3}  status"
    )
    print(header)
    print("-" * len(header))
    for r in results:
        if r.error:
            status = "ERROR"
        elif r.used_retry:
            status = "PASS_RETRY"
        elif r.ok:
            status = "PASS"
        else:
            status = "FAIL"
        print(
            f"{r.case:<{w_case}}  "
            f"{r.expected:<{w_expected}}  "
            f"{r.actual:<{w_actual}}  "
            f"{r.attempts:>3}  {status}"
        )

    n_total = len(results)
    n_pass  = sum(1 for r in results if r.ok)
    n_fail  = n_total - n_pass
    n_retry = sum(1 for r in results if r.used_retry)
    print()
    if n_fail:
        print(f"FAIL {n_fail}/{n_total} cases ({n_retry} retries succeeded)")
        print("Failed cases:")
        for r in results:
            if r.ok:
                continue
            tag = r.error or r.reason or "(no reason)"
            print(f"  - {r.case}: {tag}")
    else:
        print(f"OK {n_pass}/{n_total} cases ({n_retry} retries used)")


# ── main ────────────────────────────────────────────────────
async def _amain(args: argparse.Namespace) -> int:
    cases_dir        = Path(args.cases_dir)
    expected_path    = Path(args.expected)
    perspectives_dir = Path(args.perspectives_dir)

    if not expected_path.exists():
        print(f"error: expected file not found: {expected_path}", file=sys.stderr)
        return 2

    expected = load_expected(expected_path)
    if not expected:
        print(f"error: no cases in {expected_path}", file=sys.stderr)
        return 2

    context_text = load_context_file(args.context) if args.context else ""
    if context_text:
        print(f"[context] loaded {len(context_text)} chars from {args.context}",
              file=sys.stderr)

    print(
        f"[eval] {len(expected)} cases, "
        f"retry={'on' if not args.no_retry else 'off'}",
        file=sys.stderr,
    )

    results: list[CaseResult] = []
    for exp in expected:
        diff_path = cases_dir / f"{exp.case}.diff"
        if not diff_path.exists():
            results.append(CaseResult(
                case=exp.case, expected="?", actual="?",
                ok=False, attempts=0, used_retry=False,
                error=f"diff file not found: {diff_path}",
            ))
            continue
        results.append(await run_case(
            exp, diff_path, perspectives_dir,
            retry         = not args.no_retry,
            context_text  = context_text,
            verbose       = args.verbose,
            debate_rounds = args.debate_rounds,
        ))

    _print_report(results)
    return 0 if all(r.ok for r in results) else 1


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eval.py",
        description="Eval harness: run cases through scan_diff and compare to expected.yml.",
    )
    p.add_argument("--cases-dir", default=str(HERE / "evals" / "cases"),
                   help="default: ./evals/cases")
    p.add_argument("--expected",  default=str(HERE / "evals" / "expected.yml"),
                   help="default: ./evals/expected.yml")
    p.add_argument("--perspectives-dir", default=str(HERE / "perspectives"),
                   help="default: ./perspectives")
    p.add_argument("--context", default=None,
                   help="path to SECURITY-CONTEXT.md (optional)")
    p.add_argument("--no-retry", action="store_true",
                   help="disable retry (1 attempt only; useful for debugging)")
    p.add_argument("--debate-rounds", type=int, default=1, choices=(1, 2),
                   help="1 (default) = standard triage. 2 = run an extra rebut "
                        "round on findings that come back inconclusive.")
    p.add_argument("--verbose", action="store_true",
                   help="show per-attempt logs to stderr")
    return p


def main() -> None:
    args = build_argparser().parse_args()
    code = asyncio.run(_amain(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
