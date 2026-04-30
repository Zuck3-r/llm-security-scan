#!/usr/bin/env python3
"""過去 PR バックフィル CLI (CLAUDE.md §9 Step 1)。

`gh` で過去 PR の diff とメタデータを取得し、`src/engine.py::scan_diff()` を
プログラム経由で呼び、結果を `replays/PR-<n>.json` に書き出す。

eval ケースを手書きするより、過去 PR を回して目視で「答案確定」できたものを
`evals/cases/` に昇格させるためのフィードバックループの起点。

使い方:
    python replay.py --pr 42
    python replay.py --pr-range 1..100
    python replay.py --pr 42 --repo owner/name           # repo 自動判定の上書き
    python replay.py --pr-range 1..100 --no-triage       # コスト節約モード
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))

# scan_diff を import すると providers / triage がロードされるが env 解決は遅延。
from engine import scan_diff  # noqa: E402


# ── gh の薄いラッパー ──────────────────────────────────────
def _run_gh(args: list[str]) -> str:
    """gh CLI を呼んで stdout を返す。失敗時は CalledProcessError。"""
    if shutil.which("gh") is None:
        raise RuntimeError("`gh` CLI が見つかりません。https://cli.github.com/ をインストールしてください。")
    proc = subprocess.run(
        ["gh", *args],
        check          = True,
        capture_output = True,
        text           = True,
    )
    return proc.stdout


def _detect_repo() -> str:
    """カレント repo を `owner/name` 形式で取得する。"""
    out = _run_gh(["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"])
    return out.strip()


def fetch_pr_metadata(repo: str, pr_number: int) -> dict:
    """gh pr view で PR のメタデータを取る。"""
    out = _run_gh([
        "pr", "view", str(pr_number),
        "--repo", repo,
        "--json", "number,title,mergedAt,additions,deletions,changedFiles,baseRefName,headRefName,state",
    ])
    return json.loads(out)


def fetch_pr_diff(repo: str, pr_number: int) -> str:
    """gh pr diff で unified diff を取る。"""
    return _run_gh(["pr", "diff", str(pr_number), "--repo", repo])


# ── range parser ────────────────────────────────────────────
def parse_pr_range(spec: str) -> list[int]:
    """'1..100' / '1-100' を PR 番号 list に展開。"""
    spec = spec.strip()
    for sep in ("..", "-"):
        if sep in spec:
            a, b = spec.split(sep, 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            return list(range(lo, hi + 1))
    raise ValueError(f"invalid range spec: {spec!r} (expected 'A..B' or 'A-B')")


# ── 集計 ────────────────────────────────────────────────────
def _aggregate(ctx) -> dict:
    """ScanContext から replay JSON 用の dict を作る。dataclasses はそのまま asdict()。"""
    findings_total: list[dict] = []
    triage_counts = {"confirmed": 0, "dismissed": 0, "inconclusive": 0, "raw": 0}
    scan_in = scan_out = 0
    triage_in = triage_out = 0
    for r in ctx.results:
        scan_in  += r.tokens_in
        scan_out += r.tokens_out
        triage_in  += r.triage.tokens_in
        triage_out += r.triage.tokens_out
        for f in r.findings:
            findings_total.append(asdict(f))
            triage_counts[f.triage_status] = triage_counts.get(f.triage_status, 0) + 1
    return {
        "findings": findings_total,
        "triage":   {
            "confirmed":    triage_counts["confirmed"],
            "dismissed":    triage_counts["dismissed"],
            "inconclusive": triage_counts["inconclusive"],
            "raw":          triage_counts["raw"],
        },
        "tokens":   {
            "scan_in":    scan_in,
            "scan_out":   scan_out,
            "triage_in":  triage_in,
            "triage_out": triage_out,
        },
        "provider": ctx.provider_name,
        "model":    ctx.model,
        "triage_enabled":     ctx.triage_enabled,
        "perspectives_total": ctx.total_perspectives,
    }


# ── 1 PR を回す ─────────────────────────────────────────────
async def replay_one(
    repo:                    str,
    pr_number:               int,
    out_dir:                 Path,
    perspectives_dir:        Path,
    *,
    enable_triage:           bool,
    triage_concurrency:      int,
    max_low_per_perspective: int,
    force:                   bool,
) -> Path:
    out_path = out_dir / f"PR-{pr_number}.json"
    if out_path.exists() and not force:
        print(f"[skip] {out_path} (use --force to overwrite)", file=sys.stderr)
        return out_path

    print(f"[fetch] PR #{pr_number} from {repo}", file=sys.stderr)
    meta = fetch_pr_metadata(repo, pr_number)
    diff_text = fetch_pr_diff(repo, pr_number)

    print(f"[scan] PR #{pr_number} ({len(diff_text)} bytes diff)", file=sys.stderr)
    ctx = await scan_diff(
        diff_text,
        perspectives_dir,
        enable_triage           = enable_triage,
        triage_concurrency      = triage_concurrency,
        max_low_per_perspective = max_low_per_perspective,
    )

    payload = {
        "pr_number":  meta.get("number", pr_number),
        "title":      meta.get("title", ""),
        "state":      meta.get("state", ""),
        "merged_at":  meta.get("mergedAt"),
        "base":       meta.get("baseRefName"),
        "head":       meta.get("headRefName"),
        "diff_stats": {
            "files":     meta.get("changedFiles", 0),
            "additions": meta.get("additions", 0),
            "deletions": meta.get("deletions", 0),
        },
        **_aggregate(ctx),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[write] {out_path}", file=sys.stderr)
    return out_path


# ── main ────────────────────────────────────────────────────
async def _amain(args: argparse.Namespace) -> int:
    repo = args.repo or _detect_repo()
    print(f"[repo] {repo}", file=sys.stderr)

    if args.pr is not None and args.pr_range is not None:
        print("error: --pr と --pr-range は同時指定できません", file=sys.stderr)
        return 2

    if args.pr is not None:
        prs = [args.pr]
    elif args.pr_range is not None:
        prs = parse_pr_range(args.pr_range)
    else:
        print("error: --pr か --pr-range のどちらかを指定してください", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir)
    perspectives_dir = Path(args.perspectives_dir)

    failures = 0
    for n in prs:
        try:
            await replay_one(
                repo, n, out_dir, perspectives_dir,
                enable_triage           = not args.no_triage,
                triage_concurrency      = args.triage_concurrency,
                max_low_per_perspective = args.max_low_per_perspective,
                force                   = args.force,
            )
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr or "").strip()
            print(f"[error] PR #{n}: gh failed: {stderr[:300]}", file=sys.stderr)
            failures += 1
        except Exception as e:
            print(f"[error] PR #{n}: {type(e).__name__}: {e}", file=sys.stderr)
            failures += 1

    print(f"[done] {len(prs) - failures}/{len(prs)} PRs replayed", file=sys.stderr)
    return 1 if failures else 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="replay.py",
        description="Replay past PRs through the LLM security scan and write JSON results.",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--pr", type=int, help="single PR number to replay")
    g.add_argument("--pr-range", type=str,
                   help="PR number range, e.g. '1..100' or '1-100' (inclusive)")
    p.add_argument("--repo", default=None,
                   help="owner/name (default: auto-detect via `gh repo view`)")
    p.add_argument("--output-dir", default=str(HERE / "replays"),
                   help="directory to write PR-<n>.json files (default: ./replays)")
    p.add_argument("--perspectives-dir", default=str(HERE / "perspectives"),
                   help="perspectives directory (default: ./perspectives)")
    p.add_argument("--no-triage", action="store_true",
                   help="disable dialectical triage to save tokens")
    p.add_argument("--triage-concurrency", type=int, default=4,
                   help="max parallel triage jobs (default: 4)")
    p.add_argument("--max-low-per-perspective", type=int, default=3,
                   help="cap of Low-severity findings to triage per perspective (default: 3)")
    p.add_argument("--force", action="store_true",
                   help="overwrite existing PR-<n>.json files")
    return p


def main() -> None:
    args = build_argparser().parse_args()
    code = asyncio.run(_amain(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
