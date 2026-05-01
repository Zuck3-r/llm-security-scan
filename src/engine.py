#!/usr/bin/env python3
"""LLM ハーネスベース ホワイトボックス セキュリティ診断エンジン。

`perspectives/*.yml` を読み、enabled なものを並列で LLM に投げ、
検証ゲートを通したうえで Markdown レポートを書き出す。
観点の追加は YAML を 1 ファイル置くだけで行える（このスクリプトは無変更）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml  # type: ignore

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from validator import Finding, GateStats, validate_findings  # noqa: E402
from triage import TriageStats, triage_findings  # noqa: E402


# ── 定数 ────────────────────────────────────────────────────
SYSTEM_PROMPT_BASE = (
    "あなたはセキュリティ診断の専門家です。\n"
    "与えられたコード差分を指定された観点で分析し、指定されたJSON形式で結果を返してください。\n"
    "JSONのみを出力し、それ以外のテキストは含めないでください。\n"
    "diff の + 行（追加された行）を重点的に分析してください。\n"
)

# プロジェクト固有の文脈 (SECURITY-CONTEXT.md) を system prompt 末尾に注入する。
# 内製 framework の認証 decorator 名・独自 sanitizer・dev-only bypass のガード等を
# LLM に伝えて誤検知 (W1 訓練バイアス / W2 観測の過信) を抑える。
# 文脈は全 LLM 呼び出しで共通なので prompt cache の prefix として効く。
_CONTEXT_HEADER = (
    "\n\n## このリポジトリ固有の文脈\n"
    "以下はこのプロジェクトの慣用 / 安全装置 / 既知の例外に関する説明。\n"
    "観点の検出ルールよりこの文脈を優先せず、両方を踏まえて判定すること。\n"
    "ここで「安全」とされる経路を見たら誤検知扱いにしてよい。\n\n"
)


def build_system_prompt(context_text: str = "") -> str:
    """system prompt に SECURITY-CONTEXT を末尾追加して返す。空なら base のみ。"""
    if not context_text or not context_text.strip():
        return SYSTEM_PROMPT_BASE
    return SYSTEM_PROMPT_BASE + _CONTEXT_HEADER + context_text.strip() + "\n"


def load_context_file(path: str | None) -> str:
    """--context で渡されたファイルを読む。空 / 存在しない / None なら空文字を返す。"""
    if not path:
        return ""
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[warn] failed to read context file {path}: {e}", file=sys.stderr)
        return ""


DIFF_MAX_CHARS = 30_000


# ── 結果コンテナ ─────────────────────────────────────────────
@dataclass
class ScanResult:
    perspective_id:   str
    perspective_name: str
    severity_weight:  str
    findings:         list[Finding]      = field(default_factory=list)
    summary:          str                = ""
    excluded:         GateStats          = field(default_factory=GateStats)
    error:            str                = ""
    tokens_in:        int                = 0
    tokens_out:       int                = 0
    # Phase 2: triage 集計（観点単位）
    triage:           TriageStats        = field(default_factory=TriageStats)


# ── diff 解析 ───────────────────────────────────────────────
_RE_DIFF_HEADER     = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
_RE_NEW_FILE_PATH   = re.compile(r"^\+\+\+ b/(.+)$")


def parse_diff(diff_text: str) -> tuple[list[str], dict[str, list[str]]]:
    """unified diff から (touched_files, added_lines_per_file) を抽出する。"""
    files: list[str] = []
    added_by: dict[str, list[str]] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        m = _RE_DIFF_HEADER.match(line)
        if m:
            current = m.group(2)
            if current not in added_by:
                files.append(current)
                added_by[current] = []
            continue
        m2 = _RE_NEW_FILE_PATH.match(line)
        if m2 and current is None:
            # diff --git ヘッダなしで +++ から始まるケースの保険
            current = m2.group(1)
            if current not in added_by:
                files.append(current)
                added_by[current] = []
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if current:
                added_by[current].append(line[1:])
    return files, added_by


# ── perspectives ロード ────────────────────────────────────
def load_perspectives(perspectives_dir: Path) -> list[dict]:
    items: list[dict] = []
    for p in sorted(perspectives_dir.glob("*.yml")):
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not data.get("enabled"):
            continue
        items.append(data)
    return items


def compile_safe_patterns(perspectives: list[dict]) -> dict[str, list[re.Pattern]]:
    out: dict[str, list[re.Pattern]] = {}
    for p in perspectives:
        pats = p.get("code_safe_patterns") or []
        compiled: list[re.Pattern] = []
        for s in pats:
            try:
                compiled.append(re.compile(s))
            except re.error as e:
                print(f"[warn] invalid regex in {p.get('id')}: {s!r}: {e}", file=sys.stderr)
        out[p["id"]] = compiled
    return out


# ── プロンプト組み立て ──────────────────────────────────────
def build_user_prompt(persp: dict, diff: str) -> str:
    pr = persp.get("prompt") or {}
    detect = (pr.get("detect_patterns") or "").strip()
    safe   = (pr.get("safe_patterns")   or "").strip()
    schema = (pr.get("output_schema")   or "").strip()

    parts: list[str] = []
    parts.append(f"# 観点: {persp.get('name', persp.get('id', 'unknown'))}")
    parts.append(f"\n## 検出すべきパターン\n{detect}")
    if safe:
        parts.append(f"\n## 検出から除外すべきパターン\n{safe}")
    parts.append(f"\n## 出力形式\n{schema}")
    parts.append("\n## 対象 diff\n```diff\n" + diff + "\n```")
    return "\n".join(parts)


# ── LLM 出力の解釈 ──────────────────────────────────────────
# 3 段階方式:
#   1) ```json ... ``` または ``` ... ``` のフェンス内を取り出す
#   2) 全体を json.loads
#   3) 最後に最外の {...} を正規表現で取り出す
_RE_CODE_FENCE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)
_RE_OBJECT     = re.compile(r"\{[\s\S]*\}")


def extract_json(content: str) -> dict:
    """LLM 出力から JSON オブジェクトを取り出す。失敗時は ValueError。"""
    if not content:
        raise ValueError("empty content")
    text = content.strip()
    # 1) コードフェンス
    m = _RE_CODE_FENCE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # 2) 全体パース
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 3) {...} 抜き出し
    m2 = _RE_OBJECT.search(text)
    if m2:
        try:
            return json.loads(m2.group(0))
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON decode failed in object extract: {e}") from e
    raise ValueError("no JSON object found")


# ── 1 観点 = 1 LLM 呼び出し ──────────────────────────────
async def run_perspective(
    provider, persp: dict, diff: str, *, system_prompt: str = SYSTEM_PROMPT_BASE,
) -> ScanResult:
    res = ScanResult(
        perspective_id   = str(persp.get("id", "")).strip(),
        perspective_name = str(persp.get("name", persp.get("id", ""))).strip(),
        severity_weight  = str(persp.get("severity_weight", "Medium")).strip(),
    )
    user = build_user_prompt(persp, diff)
    try:
        out = await provider.call(system_prompt, user)
    except Exception as e:
        res.error = f"{type(e).__name__}: {e}"
        return res

    res.tokens_in  = int(out.get("tokens_in",  0) or 0)
    res.tokens_out = int(out.get("tokens_out", 0) or 0)
    raw_text = out.get("text", "") or ""
    if not raw_text.strip():
        res.error = "empty response"
        return res
    try:
        data = extract_json(raw_text)
    except ValueError as e:
        res.error = f"JSON parse failed: {e} (raw[:120]={raw_text[:120]!r})"
        return res

    res.summary = str(data.get("summary") or "").strip()
    items = data.get("findings") or []
    if not isinstance(items, list):
        res.error = "findings is not a list"
        return res

    for it in items:
        if not isinstance(it, dict):
            continue
        sev = str(it.get("severity") or res.severity_weight or "Medium").strip().capitalize()
        res.findings.append(Finding(
            file           = str(it.get("file", "")).strip(),
            line           = str(it.get("line", "")).strip(),
            severity       = sev,
            title          = str(it.get("title", "")).strip(),
            detail         = str(it.get("detail", "")).strip(),
            fix            = str(it.get("fix", "")).strip(),
            perspective_id = res.perspective_id,
        ))
    return res


# ── プログラム経由のエントリポイント ───────────────────────
@dataclass
class ScanContext:
    """`scan_diff` の戻り値。Markdown レンダリングや replay/eval の集計に使う。"""
    results:            list[ScanResult]
    provider_name:      str
    model:              str
    total_perspectives: int
    triage_enabled:     bool


async def scan_diff(
    diff_text: str,
    perspectives_dir: Path,
    *,
    enable_triage: bool = True,
    triage_concurrency: int = 4,
    max_low_per_perspective: int = 3,
    context_text: str = "",
    debate_rounds: int = 1,
) -> ScanContext:
    """diff 文字列を直接受け取り、検証ゲート＋（任意で）トリアージまで通した結果を返す。

    CLI (run_scan) と replay.py / eval.py 等の他ツールが共有する core エントリ。
    Markdown は書かない（呼び出し側で reporter.render_markdown する）。

    `context_text` が非空なら SECURITY-CONTEXT として全 LLM 呼び出しの system
    prompt 末尾に注入される。プロジェクト固有の慣用 (内製 framework の認証
    decorator 名等) を伝えて W1 / W2 の誤検知を抑える用途。
    """
    if len(diff_text) > DIFF_MAX_CHARS:
        diff_text = diff_text[:DIFF_MAX_CHARS] + "\n... (trimmed)\n"
    diff_files, added_by = parse_diff(diff_text)

    perspectives = load_perspectives(perspectives_dir)
    if not perspectives:
        return ScanContext(
            results            = [],
            provider_name      = "",
            model              = "",
            total_perspectives = 0,
            triage_enabled     = enable_triage,
        )

    # provider はここで初めて env を解決（--help では到達しない）
    from providers import get_provider
    provider = get_provider()

    # system prompt はここで 1 度だけ組み立て、全観点・全 triage ロールに同じものを
    # 渡す (prompt cache の prefix として効かせる)
    system_prompt = build_system_prompt(context_text)

    # 並列実行
    tasks = [run_perspective(provider, p, diff_text, system_prompt=system_prompt) for p in perspectives]
    results: list[ScanResult] = list(await asyncio.gather(*tasks))

    # 検証ゲート
    safe_pats = compile_safe_patterns(perspectives)
    for r in results:
        validated, stats = validate_findings(r.findings, diff_files, added_by, safe_pats)
        r.findings = validated
        r.excluded = stats

    # ── Phase 2: 弁証法的トリアージ ─────────────────────────
    # 検証ゲートを通過した finding 群に対して、Attacker/Defender/Judge の
    # 独立呼び出しで再判定。confirmed/dismissed/inconclusive を付与し、
    # confirmed の場合は最小 PoC を埋める。
    if enable_triage:
        # 観点単位で並列に triage（観点間も並列化）
        async def _triage_for(r: ScanResult):
            r.findings, r.triage = await triage_findings(
                provider,
                r.findings,
                added_by,
                max_low_per_perspective = max_low_per_perspective,
                concurrency             = triage_concurrency,
                context_text            = context_text,
                debate_rounds           = debate_rounds,
            )
        await asyncio.gather(*[_triage_for(r) for r in results if r.findings])

    return ScanContext(
        results            = results,
        provider_name      = provider.name,
        model              = provider.model,
        total_perspectives = len(perspectives),
        triage_enabled     = enable_triage,
    )


# ── CLI ラッパー ────────────────────────────────────────────
async def run_scan(
    diff_path: str,
    output_path: str,
    perspectives_dir: Path,
    *,
    enable_triage: bool = True,
    triage_concurrency: int = 4,
    max_low_per_perspective: int = 3,
    context_path: str | None = None,
    debate_rounds: int = 1,
) -> int:
    diff_text = sys.stdin.read() if diff_path == "-" else Path(diff_path).read_text(encoding="utf-8")
    context_text = load_context_file(context_path)

    ctx = await scan_diff(
        diff_text,
        perspectives_dir,
        enable_triage           = enable_triage,
        triage_concurrency      = triage_concurrency,
        max_low_per_perspective = max_low_per_perspective,
        context_text            = context_text,
        debate_rounds           = debate_rounds,
    )

    if ctx.total_perspectives == 0:
        Path(output_path).write_text(
            "# 🛡️ LLM Security Scan\n\nNo enabled perspectives.\n",
            encoding="utf-8",
        )
        return 0

    from reporter import render_markdown
    md = render_markdown(
        ctx.results,
        provider_name      = ctx.provider_name,
        model              = ctx.model,
        total_perspectives = ctx.total_perspectives,
        triage_enabled     = ctx.triage_enabled,
    )
    Path(output_path).write_text(md, encoding="utf-8")
    return 0


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="engine.py",
        description="LLM harness-based whitebox security scan",
    )
    parser.add_argument("--diff",   required=True,
                        help="path to unified diff (use '-' to read stdin)")
    parser.add_argument("--output", required=True,
                        help="path to write the Markdown report")
    parser.add_argument("--perspectives-dir", default=str(HERE.parent / "perspectives"),
                        help="directory containing *.yml perspective definitions")
    parser.add_argument("--context", default=None,
                        help="path to a SECURITY-CONTEXT markdown file. its contents are "
                             "appended to the system prompt of every LLM call (scan + triage). "
                             "missing/empty file is treated as no context (no-op).")
    # ── Phase 2 の triage 制御 ─────────────────────────────
    parser.add_argument("--no-triage", action="store_true",
                        help="disable dialectical triage (Phase 1 behavior)")
    parser.add_argument("--triage-concurrency", type=int, default=4,
                        help="max parallel triage jobs (default: 4)")
    parser.add_argument("--max-low-per-perspective", type=int, default=3,
                        help="cap of Low-severity findings to triage per perspective "
                             "(default: 3; rest stay status=raw)")
    parser.add_argument("--debate-rounds", type=int, default=1, choices=(1, 2),
                        help="number of debate rounds in triage. 1 (default) = "
                             "Attacker/Defender/Judge once. 2 = run an extra "
                             "Attacker_rebut/Defender_rebut/Judge round on findings "
                             "that come back inconclusive.")
    return parser


def main() -> None:
    args = build_argparser().parse_args()
    code = asyncio.run(run_scan(
        args.diff,
        args.output,
        Path(args.perspectives_dir),
        enable_triage           = not args.no_triage,
        triage_concurrency      = args.triage_concurrency,
        max_low_per_perspective = args.max_low_per_perspective,
        context_path            = args.context,
        debate_rounds           = args.debate_rounds,
    ))
    sys.exit(code)


if __name__ == "__main__":
    main()
