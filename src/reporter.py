"""Markdown レポート生成。
スティッキーコメントとして PR に投稿される最終アウトプット。
"""
from __future__ import annotations

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
SEVERITY_BADGE = {
    "Critical": "🔴 Critical",
    "High":     "🟠 High",
    "Medium":   "🟡 Medium",
    "Low":      "🔵 Low",
}

# Phase 2: triage の判定バッジ
TRIAGE_BADGE = {
    "confirmed":    "🎯 Confirmed",
    "dismissed":    "🛡️ Dismissed (likely FP)",
    "inconclusive": "❓ Inconclusive",
    "raw":          "📋 Not triaged",
}

# Phase 3: confidence < この閾値の dismissed は折り畳まず人手レビュー対象として残す
LOW_CONFIDENCE_DISMISSED_THRESHOLD = 0.6


def _severity_badge(s: str) -> str:
    return SEVERITY_BADGE.get(s, f"⚪ {s}")


def _triage_badge(s: str) -> str:
    return TRIAGE_BADGE.get(s, f"📋 {s or 'raw'}")


def _confidence_badge(c: float) -> str:
    if c >= 0.9:
        return f"({c:.2f} 確信)"
    if c >= 0.6:
        return f"({c:.2f})"
    if c > 0:
        return f"({c:.2f} ⚠️ 低確信)"
    return ""


def _poc_lang_hint(kind: str) -> str:
    return {
        "http_request": "http",
        "curl":         "bash",
        "code":         "",     # 言語判定は LLM 任せ
        "payload":      "",
        "none":         "",
    }.get((kind or "").lower(), "")


def _render_finding(lines: list, persp_name: str, f, triage_enabled: bool) -> None:
    """1 finding を Markdown に追記する。triage_enabled 時は Attacker/Defender/Judge 結果も出す。"""
    title = f.title or "(no title)"
    head_badges = [_severity_badge(f.severity)]
    if triage_enabled:
        status_badge = _triage_badge(getattr(f, "triage_status", "raw"))
        conf_badge   = _confidence_badge(float(getattr(f, "triage_confidence", 0.0) or 0.0))
        if conf_badge:
            head_badges.append(f"{status_badge} {conf_badge}")
        else:
            head_badges.append(status_badge)
    lines.append(f"### {' '.join(head_badges)} — {title}")
    lines.append("")
    lines.append(f"- **ファイル**: `{f.file}` （行: {f.line or '-'}）")
    lines.append(f"- **観点**: {persp_name}")

    # triage が走っていれば判定理由・主張を出す
    if triage_enabled:
        reason = getattr(f, "triage_reason", "")
        if reason:
            lines.append(f"- **Judge**: {reason}")
        a = getattr(f, "attacker_arg", "")
        d = getattr(f, "defender_arg", "")
        if a or d:
            lines.append("")
            if a:
                lines.append(f"  - 🎯 _Attacker_: {a}")
            if d:
                lines.append(f"  - 🛡️ _Defender_: {d}")

    if f.detail:
        lines.append("- **詳細**:")
        lines.append("")
        for ln in f.detail.splitlines():
            lines.append(f"  > {ln}")
        lines.append("")

    # PoC（Attacker が exploitable と主張した場合のみ）
    poc = getattr(f, "poc", "")
    if triage_enabled and poc:
        kind = getattr(f, "poc_kind", "")
        lang = _poc_lang_hint(kind)
        lines.append(f"- **最小再現 PoC** ({kind or 'snippet'}):")
        lines.append("")
        lines.append(f"  ```{lang}".rstrip())
        for ln in poc.splitlines():
            lines.append(f"  {ln}")
        lines.append("  ```")
        lines.append("")

    if f.fix:
        lines.append("- **修正案**:")
        lines.append("")
        for ln in f.fix.splitlines():
            lines.append(f"  > {ln}")
        lines.append("")

    err = getattr(f, "triage_error", "")
    if triage_enabled and err:
        lines.append(f"- _triage_error_: `{err}`")
    lines.append("")


def render_markdown(
    results: list,            # list[ScanResult]
    *,
    provider_name: str,
    model: str,
    total_perspectives: int,
    triage_enabled: bool = False,
) -> str:
    lines: list[str] = []
    lines.append("# 🛡️ LLM Security Scan")
    lines.append("")

    total_findings = sum(len(r.findings) for r in results)
    total_excluded = sum(r.excluded.total   for r in results)
    has_error      = any(r.error           for r in results)

    # Phase 2 集計
    confirmed_total    = sum(r.triage.confirmed    for r in results) if triage_enabled else 0
    dismissed_total    = sum(r.triage.dismissed    for r in results) if triage_enabled else 0
    inconclusive_total = sum(r.triage.inconclusive for r in results) if triage_enabled else 0

    if total_findings == 0 and not has_error:
        lines.append(
            f"✅ **検出 0 件** — {total_perspectives} 観点をスキャンし、"
            f"検証ゲート通過後の指摘はありませんでした。"
        )
    elif total_findings == 0 and has_error:
        lines.append(
            f"⚠️ スキャンの一部観点でエラーが発生しました（下表参照）。"
            f"検出 0 件ですが結果は不完全です。"
        )
    elif triage_enabled:
        lines.append(
            f"⚠️ **検出 {total_findings} 件** — "
            f"🎯 confirmed: {confirmed_total} / "
            f"🛡️ dismissed: {dismissed_total} / "
            f"❓ inconclusive: {inconclusive_total}"
        )
    else:
        lines.append(f"⚠️ **検出 {total_findings} 件** — 下記の検出詳細を確認してください。")
    lines.append("")

    # ── 観点サマリーテーブル ────────────────────────────────
    lines.append("## 観点サマリー")
    lines.append("")
    lines.append("| 観点 | 結果 | 検出 | 除外（ゲート） | エラー |")
    lines.append("|------|------|-----:|---------------:|--------|")
    for r in results:
        if r.error:
            status = "❌ エラー"
        elif r.findings:
            status = "⚠️ 検出"
        else:
            status = "✅ なし"
        err_cell = (r.error[:80] + "…") if r.error and len(r.error) > 80 else (r.error or "-")
        lines.append(
            f"| {r.perspective_name} | {status} | {len(r.findings)} | "
            f"{r.excluded.total} | {err_cell} |"
        )
    lines.append("")

    # ── 観点別の評価（LLM の summary）────────────────────────
    if any(r.summary for r in results):
        lines.append("## 観点別の評価")
        lines.append("")
        for r in results:
            if r.summary:
                lines.append(f"- **{r.perspective_name}**: {r.summary}")
        lines.append("")

    # ── 検出詳細（triage 後 → confirmed/inconclusive を上に、dismissed は折り畳み）
    if total_findings > 0:
        all_findings: list[tuple[str, object]] = []
        for r in results:
            for f in r.findings:
                all_findings.append((r.perspective_name, f))

        # ソート: triage 順位 (confirmed=2, inconclusive=1, raw=0, dismissed=-1) ↓
        # → severity ↓ で安定ソート
        def _triage_rank(s: str) -> int:
            return {"confirmed": 2, "inconclusive": 1, "raw": 0, "dismissed": -1}.get(s, 0)

        if triage_enabled:
            all_findings.sort(
                key=lambda x: (
                    -_triage_rank(getattr(x[1], "triage_status", "raw")),
                    -SEVERITY_RANK.get(x[1].severity, 0),
                )
            )
        else:
            all_findings.sort(key=lambda x: -SEVERITY_RANK.get(x[1].severity, 0))

        # confirmed/inconclusive/raw を main セクションに出し、dismissed は折り畳み。
        # ただし confidence < LOW_CONFIDENCE_DISMISSED_THRESHOLD の dismissed は
        # 「Judge が自信を持って FP と言い切れていない」ため人手レビューに残す。
        def _is_high_conf_dismissed(f) -> bool:
            return (
                getattr(f, "triage_status", "raw") == "dismissed"
                and float(getattr(f, "triage_confidence", 0.0) or 0.0)
                    >= LOW_CONFIDENCE_DISMISSED_THRESHOLD
            )

        primary   = [(p, f) for (p, f) in all_findings if not _is_high_conf_dismissed(f)]
        dismissed = [(p, f) for (p, f) in all_findings if     _is_high_conf_dismissed(f)]

        if primary:
            lines.append("## 検出詳細")
            lines.append("")
            for persp_name, f in primary:
                _render_finding(lines, persp_name, f, triage_enabled)

        if dismissed:
            lines.append("<details>")
            lines.append(f"<summary>🛡️ Dismissed (LLM トリアージで偽陽性判定: "
                         f"{len(dismissed)} 件) — クリックで展開</summary>")
            lines.append("")
            for persp_name, f in dismissed:
                _render_finding(lines, persp_name, f, triage_enabled)
            lines.append("</details>")
            lines.append("")

    # ── フッタ（透明性: 除外内訳・トークン消費） ────────────
    sub_excluded_breakdown = {
        "schema":   sum(r.excluded.schema_rejected for r in results),
        "missing":  sum(r.excluded.file_missing    for r in results),
        "dup":      sum(r.excluded.duplicate       for r in results),
        "safe":     sum(r.excluded.safe_pattern    for r in results),
    }
    tokens_in  = sum(r.tokens_in  for r in results)
    tokens_out = sum(r.tokens_out for r in results)
    triage_in  = sum(r.triage.tokens_in  for r in results) if triage_enabled else 0
    triage_out = sum(r.triage.tokens_out for r in results) if triage_enabled else 0
    triage_skipped_low = sum(r.triage.skipped_low for r in results) if triage_enabled else 0

    lines.append("---")
    footer = (
        f"Provider: <code>{provider_name}</code> / Model: <code>{model}</code> / "
        f"観点: {total_perspectives} / "
        f"除外: {total_excluded} "
        f"(schema={sub_excluded_breakdown['schema']}, "
        f"missing={sub_excluded_breakdown['missing']}, "
        f"dup={sub_excluded_breakdown['dup']}, "
        f"safe={sub_excluded_breakdown['safe']}) / "
        f"Tokens: scan in={tokens_in} out={tokens_out}"
    )
    if triage_enabled:
        footer += (
            f" / Triage: in={triage_in} out={triage_out}"
            f" (confirmed={confirmed_total}, dismissed={dismissed_total}, "
            f"inconclusive={inconclusive_total}, low_skipped={triage_skipped_low})"
        )
    lines.append(f"<sub>{footer}</sub>")
    return "\n".join(lines) + "\n"
