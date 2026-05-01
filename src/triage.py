"""Phase 2: 弁証法的トリアージ（dialectical triage）。

検証ゲート (validator.py) を通過した finding に対して、
独立した LLM 呼び出しを 3 つ走らせ、最終確度を再判定する。

  Attacker — exploitable 前提で最小 PoC を組み立てる（攻撃側の主張）
  Defender — false positive 仮説で反証する（防御側の主張）
  Judge    — 両者を読み confirmed / dismissed / inconclusive を判定

設計上の原則（Phase 2 でも維持）:
  - 1 finding につき独立した API 呼び出し（W3 コンテキスト限界の緩和）
  - 出力は JSON スキーマ強制。失敗は fail-open（finding を消さない）
  - 並列実行 (asyncio.gather)
  - 観点ごとに上位 N 件のみ triage（コスト上限。下位の Low はスキップ）
  - 既存 finding 構造を破壊しない（追加フィールドのみ）
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml  # type: ignore

from validator import Finding


# ── プロンプト読み込み ────────────────────────────────────────
# triage_prompts.yml に置いた system / output_schema を起動時にロードする。
# YAML を読めない / 必要キーが欠けている場合はモジュール内のフォールバック
# (英語版) に切り替える。プロンプト編集はコード変更なしで PR レビュー可能。

_PROMPTS_PATH = Path(__file__).resolve().parent.parent / "triage_prompts.yml"


def _fallback_prompts() -> dict:
    """YAML 読込失敗時の最終防衛線（最小英語版）。"""
    return {
        "attacker": {
            "system": (
                "You are an offensive security researcher. Assume the finding is "
                "exploitable and produce one minimal PoC. Output strictly JSON only."
            ),
            "output_schema": (
                'JSON: {"exploitable": bool, "argument": "日本語 1-3 sentences", '
                '"poc": "code or payload", "poc_kind": "http_request|curl|code|payload|none"}'
            ),
        },
        "defender": {
            "system": (
                "You are a defensive code reviewer. Consider whether the finding is a "
                "false positive given existing safety mechanisms. Output strictly JSON only."
            ),
            "output_schema": (
                'JSON: {"false_positive": bool, "argument": "日本語 1-3 sentences", '
                '"safe_evidence": "1-2 lines from code"}'
            ),
        },
        "judge": {
            "system": (
                "You are a neutral judge. Read Attacker and Defender, then output one "
                "of confirmed/dismissed/inconclusive. Output strictly JSON only."
            ),
            "output_schema": (
                'JSON: {"verdict": "confirmed|dismissed|inconclusive", '
                '"reason": "日本語 1-2 sentences"}'
            ),
        },
        # Step 4: rebut ロールの fallback（YAML が古くて attacker_rebut/defender_rebut
        # を持っていない場合の保険）
        "attacker_rebut": {
            "system": (
                "You are an offensive security researcher in round 2 of a debate. "
                "Address the Defender's rebuttal and either produce a stronger PoC "
                "or concede. Output strictly JSON only."
            ),
            "output_schema": (
                'JSON: {"exploitable_after_rebut": bool, "argument": "日本語 1-3 sentences", '
                '"poc_v2": "code or payload (\"\" if cannot bypass)", '
                '"poc_kind": "http_request|curl|code|payload|none"}'
            ),
        },
        "defender_rebut": {
            "system": (
                "You are a defensive code reviewer in round 2 of a debate. "
                "Decide whether the Attacker's PoC v2 also fails against existing "
                "safety mechanisms, or concede. Output strictly JSON only."
            ),
            "output_schema": (
                'JSON: {"still_false_positive": bool, "argument": "日本語 1-3 sentences", '
                '"safe_evidence": "code line (\"\" if conceding)"}'
            ),
        },
    }


# rebut ロールは旧 YAML との互換のため optional 扱い。欠けていたら fallback で補完。
_REBUT_ROLES = ("attacker_rebut", "defender_rebut")


def _load_prompts() -> dict:
    fallback = _fallback_prompts()
    try:
        if _PROMPTS_PATH.exists():
            with open(_PROMPTS_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            # 必須ロール 3 つ
            for role in ("attacker", "defender", "judge"):
                if not (data.get(role) or {}).get("system"):
                    raise ValueError(f"{role}.system missing in {_PROMPTS_PATH}")
                if not (data.get(role) or {}).get("output_schema"):
                    raise ValueError(f"{role}.output_schema missing in {_PROMPTS_PATH}")
            # rebut ロール (optional): 欠けていたら fallback で補う
            for role in _REBUT_ROLES:
                if not (data.get(role) or {}).get("system"):
                    data[role] = fallback[role]
                elif not (data.get(role) or {}).get("output_schema"):
                    data[role]["output_schema"] = fallback[role]["output_schema"]
            return data
    except Exception as e:
        # 起動時のため stderr に警告のみ。実行は fallback で続行する。
        import sys
        print(f"[warn] triage_prompts.yml load failed, using fallback: {e}",
              file=sys.stderr)
    return fallback


_PROMPTS = _load_prompts()


# ── 上位を triage する閾値（コスト制御） ───────────────────────
# severity Critical/High/Medium は全件、Low は観点ごとに上位 N 件まで
SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
DEFAULT_MAX_LOW_PER_PERSPECTIVE = 3


# ── プロンプト（YAML から読み込んだ値を使う）─────────────────
# system prompt はロールごとに短く独立。Phase 1 と同じ最小介入の原則。

_ATTACKER_SYSTEM = _PROMPTS["attacker"]["system"]
_DEFENDER_SYSTEM = _PROMPTS["defender"]["system"]
_JUDGE_SYSTEM    = _PROMPTS["judge"]["system"]

_ATTACKER_OUTPUT_SCHEMA = _PROMPTS["attacker"]["output_schema"]
_DEFENDER_OUTPUT_SCHEMA = _PROMPTS["defender"]["output_schema"]
_JUDGE_OUTPUT_SCHEMA    = _PROMPTS["judge"]["output_schema"]

# Step 4: multi-round debate role prompts
_ATTACKER_REBUT_SYSTEM = _PROMPTS["attacker_rebut"]["system"]
_DEFENDER_REBUT_SYSTEM = _PROMPTS["defender_rebut"]["system"]
_ATTACKER_REBUT_OUTPUT_SCHEMA = _PROMPTS["attacker_rebut"]["output_schema"]
_DEFENDER_REBUT_OUTPUT_SCHEMA = _PROMPTS["defender_rebut"]["output_schema"]

# プロジェクト固有の文脈 (SECURITY-CONTEXT.md) を triage の各ロール system prompt
# 末尾に注入する。engine._CONTEXT_HEADER と同じ wording を triage 用に少し調整。
_CONTEXT_HEADER = (
    "\n\n## このリポジトリ固有の文脈\n"
    "以下はこのプロジェクトの慣用 / 安全装置 / 既知の例外に関する説明。\n"
    "このロールの判定は、観点ルールとこの文脈の双方を踏まえて行うこと。\n\n"
)


def _with_context(system_prompt: str, context_text: str) -> str:
    """ロール system prompt 末尾に SECURITY-CONTEXT を追加して返す。空文字なら no-op。"""
    if not context_text or not context_text.strip():
        return system_prompt
    return system_prompt + _CONTEXT_HEADER + context_text.strip() + "\n"


def _build_finding_block(f: Finding, code_context: str) -> str:
    """Attacker / Defender / Judge 共通で渡す finding コンテキスト。"""
    return (
        f"## 指摘内容\n"
        f"- 観点: {f.perspective_id}\n"
        f"- ファイル: {f.file}\n"
        f"- 行: {f.line}\n"
        f"- 重要度: {f.severity}\n"
        f"- タイトル: {f.title}\n"
        f"- 詳細:\n{f.detail}\n"
        f"- 現状の修正提案:\n{f.fix}\n"
        f"\n## 該当ファイルの diff 追加行（参考）\n"
        f"```\n{code_context or '(該当行を特定できず)'}\n```\n"
    )


# ── JSON 抽出（engine.py と同じ 3 段階方式） ─────────────────
_RE_CODE_FENCE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.IGNORECASE)
_RE_OBJECT     = re.compile(r"\{[\s\S]*\}")


def _extract_json(content: str) -> dict:
    if not content:
        raise ValueError("empty content")
    text = content.strip()
    m = _RE_CODE_FENCE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m2 = _RE_OBJECT.search(text)
    if m2:
        try:
            return json.loads(m2.group(0))
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON decode in object extract: {e}") from e
    raise ValueError("no JSON object found")


# ── 各ロール呼び出し（fail-open） ──────────────────────────────
@dataclass
class _RoleResult:
    data:       dict
    tokens_in:  int = 0
    tokens_out: int = 0
    error:      str = ""


async def _call_role(
    provider, system_prompt: str, user_prompt: str
) -> _RoleResult:
    try:
        out = await provider.call(system_prompt, user_prompt)
    except Exception as e:
        return _RoleResult(data={}, error=f"{type(e).__name__}: {e}")
    text = (out.get("text") or "").strip()
    if not text:
        return _RoleResult(
            data={}, tokens_in=int(out.get("tokens_in", 0) or 0),
            tokens_out=int(out.get("tokens_out", 0) or 0), error="empty response"
        )
    try:
        data = _extract_json(text)
    except ValueError as e:
        return _RoleResult(
            data={}, tokens_in=int(out.get("tokens_in", 0) or 0),
            tokens_out=int(out.get("tokens_out", 0) or 0),
            error=f"JSON parse failed: {e}",
        )
    return _RoleResult(
        data=data,
        tokens_in=int(out.get("tokens_in", 0) or 0),
        tokens_out=int(out.get("tokens_out", 0) or 0),
    )


def _apply_judge_to_finding(f: Finding, judge_data: dict) -> None:
    """Judge の dict を Finding に反映する小さなヘルパ。Round 1 / 2 共通。"""
    verdict = str(judge_data.get("verdict", "")).strip().lower()
    reason  = str(judge_data.get("reason",  "")).strip()
    try:
        conf = float(judge_data.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    conf = max(0.0, min(1.0, conf))
    if verdict == "confirmed":
        f.triage_status = "confirmed"
    elif verdict == "dismissed":
        f.triage_status = "dismissed"
    else:
        f.triage_status = "inconclusive"
    f.triage_confidence = conf
    f.triage_reason     = reason


async def _triage_one(
    provider, f: Finding, code_context: str,
    *,
    context_text:  str = "",
    debate_rounds: int = 1,
) -> tuple[Finding, int, int]:
    """1 finding に対して Attacker / Defender / Judge を順に呼ぶ。

    Round 1 は常に走る（Attacker と Defender は並列、Judge はその結果を待つ）。
    `debate_rounds >= 2` かつ Round 1 の verdict が inconclusive のときだけ
    Round 2 (Attacker_rebut + Defender_rebut + Judge 再判定) を走らせる。
    confirmed / dismissed には追加ラウンドを当てない（コスト最適化）。

    fail-open: いずれかが失敗しても finding は消さず inconclusive にする。
    `context_text` が非空なら全ロールの system prompt 末尾に注入される。
    """
    block = _build_finding_block(f, code_context)
    attacker_user = block + _ATTACKER_OUTPUT_SCHEMA
    defender_user = block + _DEFENDER_OUTPUT_SCHEMA

    attacker_sys       = _with_context(_ATTACKER_SYSTEM,       context_text)
    defender_sys       = _with_context(_DEFENDER_SYSTEM,       context_text)
    judge_sys          = _with_context(_JUDGE_SYSTEM,          context_text)
    attacker_rebut_sys = _with_context(_ATTACKER_REBUT_SYSTEM, context_text)
    defender_rebut_sys = _with_context(_DEFENDER_REBUT_SYSTEM, context_text)

    # ── Round 1 ─────────────────────────────────────────────
    attacker_res, defender_res = await asyncio.gather(
        _call_role(provider, attacker_sys, attacker_user),
        _call_role(provider, defender_sys, defender_user),
    )

    tokens_in  = attacker_res.tokens_in  + defender_res.tokens_in
    tokens_out = attacker_res.tokens_out + defender_res.tokens_out

    a_ok = not attacker_res.error and attacker_res.data
    d_ok = not defender_res.error and defender_res.data

    if not a_ok and not d_ok:
        # 両方コケた → fail-open
        f.triage_status = "inconclusive"
        f.triage_error  = f"attacker={attacker_res.error}; defender={defender_res.error}"
        return f, tokens_in, tokens_out

    if a_ok:
        f.attacker_arg = str(attacker_res.data.get("argument", "")).strip()
        if attacker_res.data.get("exploitable"):
            f.poc      = str(attacker_res.data.get("poc", "")).strip()
            f.poc_kind = str(attacker_res.data.get("poc_kind", "none")).strip().lower()
    if d_ok:
        f.defender_arg = str(defender_res.data.get("argument", "")).strip()

    judge_user = (
        block
        + "\n## Attacker の主張\n"
        + (f.attacker_arg or "(取得失敗)")
        + ("\nPoC:\n" + f.poc if f.poc else "")
        + "\n\n## Defender の反証\n"
        + (f.defender_arg or "(取得失敗)")
        + "\n"
        + _JUDGE_OUTPUT_SCHEMA
    )
    judge_res = await _call_role(provider, judge_sys, judge_user)
    tokens_in  += judge_res.tokens_in
    tokens_out += judge_res.tokens_out

    if judge_res.error or not judge_res.data:
        f.triage_status = "inconclusive"
        f.triage_error  = f"judge={judge_res.error}"
        return f, tokens_in, tokens_out

    _apply_judge_to_finding(f, judge_res.data)
    f.triage_rounds = 1

    # ── Round 2 (inconclusive のみ) ──────────────────────────
    if debate_rounds < 2 or f.triage_status != "inconclusive":
        return f, tokens_in, tokens_out

    # Attacker_rebut: Defender の反証を踏まえて PoC を強化 or concede
    rebut_block = (
        block
        + "\n## Round 1 で出た Attacker の主張\n"
        + (f.attacker_arg or "(取得失敗)")
        + ("\n初期 PoC:\n" + f.poc if f.poc else "")
        + "\n\n## Round 1 で出た Defender の反証 (これに対応せよ)\n"
        + (f.defender_arg or "(取得失敗)")
        + "\n"
    )
    attacker_rebut_user = rebut_block + _ATTACKER_REBUT_OUTPUT_SCHEMA
    attacker_rebut_res = await _call_role(provider, attacker_rebut_sys, attacker_rebut_user)
    tokens_in  += attacker_rebut_res.tokens_in
    tokens_out += attacker_rebut_res.tokens_out

    if attacker_rebut_res.error or not attacker_rebut_res.data:
        # Round 2 失敗 → Round 1 の inconclusive のまま据え置き (fail-open)
        f.triage_error = (f.triage_error + "; " if f.triage_error else "") \
                         + f"attacker_rebut={attacker_rebut_res.error}"
        return f, tokens_in, tokens_out

    f.attacker_arg_rebut = str(attacker_rebut_res.data.get("argument", "")).strip()
    poc_v2 = str(attacker_rebut_res.data.get("poc_v2", "")).strip()
    if attacker_rebut_res.data.get("exploitable_after_rebut") and poc_v2:
        f.poc      = poc_v2
        f.poc_kind = str(attacker_rebut_res.data.get("poc_kind", "none")).strip().lower()

    # Defender_rebut: 強化された PoC v2 にも反証できるか
    defender_rebut_block = (
        rebut_block
        + "\n## Attacker の Round 2 反論 (これに対応せよ)\n"
        + (f.attacker_arg_rebut or "(取得失敗)")
        + ("\nPoC v2:\n" + poc_v2 if poc_v2 else "")
        + "\n"
    )
    defender_rebut_user = defender_rebut_block + _DEFENDER_REBUT_OUTPUT_SCHEMA
    defender_rebut_res  = await _call_role(provider, defender_rebut_sys, defender_rebut_user)
    tokens_in  += defender_rebut_res.tokens_in
    tokens_out += defender_rebut_res.tokens_out

    if defender_rebut_res.error or not defender_rebut_res.data:
        f.triage_error = (f.triage_error + "; " if f.triage_error else "") \
                         + f"defender_rebut={defender_rebut_res.error}"
        return f, tokens_in, tokens_out

    f.defender_arg_rebut = str(defender_rebut_res.data.get("argument", "")).strip()

    # Judge 再判定: Round 1+2 全部の主張を提示
    judge_user_v2 = (
        block
        + "\n## Attacker の主張 (Round 1)\n" + (f.attacker_arg or "(取得失敗)")
        + ("\nPoC:\n" + f.poc if f.poc else "")
        + "\n\n## Defender の反証 (Round 1)\n" + (f.defender_arg or "(取得失敗)")
        + "\n\n## Attacker の反論 (Round 2)\n" + (f.attacker_arg_rebut or "(取得失敗)")
        + "\n\n## Defender の再反証 (Round 2)\n" + (f.defender_arg_rebut or "(取得失敗)")
        + "\n\n注: Round 2 を踏まえて再判定すること。Round 1 の判定に縛られなくてよい。\n"
        + _JUDGE_OUTPUT_SCHEMA
    )
    judge_v2_res = await _call_role(provider, judge_sys, judge_user_v2)
    tokens_in  += judge_v2_res.tokens_in
    tokens_out += judge_v2_res.tokens_out

    if judge_v2_res.error or not judge_v2_res.data:
        # Round 2 の Judge が失敗 → Round 1 の判定を維持 (inconclusive)
        f.triage_error = (f.triage_error + "; " if f.triage_error else "") \
                         + f"judge_v2={judge_v2_res.error}"
        return f, tokens_in, tokens_out

    _apply_judge_to_finding(f, judge_v2_res.data)
    f.triage_rounds = 2
    return f, tokens_in, tokens_out


# ── 上位 N 件選別（コスト制御） ────────────────────────────────
def _select_for_triage(
    findings: list[Finding], max_low_per_perspective: int
) -> tuple[list[Finding], list[Finding]]:
    """Critical/High/Medium は全件、Low は観点ごとに上位 N 件のみ triage。
    Low の超過分は triage せず status="raw" のまま返す。
    """
    queued:  list[Finding] = []
    skipped: list[Finding] = []
    low_count_per_persp: dict[str, int] = {}
    for f in findings:
        if f.severity == "Low":
            c = low_count_per_persp.get(f.perspective_id, 0)
            if c >= max_low_per_perspective:
                skipped.append(f)
                continue
            low_count_per_persp[f.perspective_id] = c + 1
        queued.append(f)
    return queued, skipped


# ── 該当ファイルの diff 追加行を抜き出す helper ───────────────
def _code_context_for(
    f: Finding, diff_added_lines_by_file: dict[str, list[str]]
) -> str:
    """validator.matches_known_safe_pattern と同じパス比較ロジック。"""
    file_norm = f.file.replace("\\", "/").lstrip("./")
    block = diff_added_lines_by_file.get(file_norm)
    if block:
        return "\n".join(block)
    for k, v in diff_added_lines_by_file.items():
        nk = k.replace("\\", "/").lstrip("./")
        if nk == file_norm:
            return "\n".join(v)
        if nk.endswith("/" + file_norm) or file_norm.endswith("/" + nk):
            return "\n".join(v)
    return ""


# ── 公開エントリ ───────────────────────────────────────────────
@dataclass
class TriageStats:
    triaged:        int = 0
    confirmed:      int = 0
    dismissed:      int = 0
    inconclusive:   int = 0
    skipped_low:    int = 0
    tokens_in:      int = 0
    tokens_out:     int = 0
    # Step 4: multi-round 統計 (debate_rounds=2 のときのみ非ゼロ)
    rebutted:       int = 0   # Round 2 を実際に走らせた件数
    flipped_to_confirmed: int = 0   # Round 1 inconclusive → Round 2 で confirmed に倒れた
    flipped_to_dismissed: int = 0   # Round 1 inconclusive → Round 2 で dismissed に倒れた


async def triage_findings(
    provider,
    findings: list[Finding],
    diff_added_lines_by_file: dict[str, list[str]],
    *,
    max_low_per_perspective: int = DEFAULT_MAX_LOW_PER_PERSPECTIVE,
    concurrency: int = 4,
    context_text: str = "",
    debate_rounds: int = 1,
) -> tuple[list[Finding], TriageStats]:
    """全 finding を triage する。並列度は `concurrency` で制限。

    返り値: (更新済み finding list, 集計値)
    findings の順序・件数は変えない（Phase 1 後段の互換性維持）。

    `context_text` は SECURITY-CONTEXT.md の中身。各ロールの system prompt
    末尾に注入される。空なら何もしない。
    `debate_rounds=2` で Step 4 の multi-round debate を有効化（Round 1 で
    Judge が inconclusive を出した finding のみ追加ラウンドを回す）。
    default は 1（現状互換）。
    """
    stats = TriageStats()
    if not findings:
        return findings, stats

    queued, skipped = _select_for_triage(findings, max_low_per_perspective)
    stats.skipped_low = len(skipped)
    for f in skipped:
        f.triage_status = "raw"  # 明示

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _bounded(f: Finding) -> tuple[Finding, int, int]:
        async with sem:
            ctx = _code_context_for(f, diff_added_lines_by_file)
            return await _triage_one(
                provider, f, ctx,
                context_text=context_text,
                debate_rounds=debate_rounds,
            )

    results = await asyncio.gather(*[_bounded(f) for f in queued])

    for f, ti, to in results:
        stats.triaged += 1
        stats.tokens_in  += ti
        stats.tokens_out += to
        if f.triage_status == "confirmed":
            stats.confirmed += 1
        elif f.triage_status == "dismissed":
            stats.dismissed += 1
        else:
            stats.inconclusive += 1
        # multi-round 統計: triage_rounds=2 → Round 2 を走らせた
        if f.triage_rounds >= 2:
            stats.rebutted += 1
            if f.triage_status == "confirmed":
                stats.flipped_to_confirmed += 1
            elif f.triage_status == "dismissed":
                stats.flipped_to_dismissed += 1

    return findings, stats
