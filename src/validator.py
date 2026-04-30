"""検証ゲート / 偽陽性フィルタ。

LLM の構造的弱点（W1–W4）を「プロンプトの注意書き」ではなく「コード側の検証」で
受け止める。perspectives/*.yml の `code_safe_patterns:` を観点単位で読み込み、
diff の追加行に該当すれば finding を除外する。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

VALID_SEVERITY = ("Critical", "High", "Medium", "Low")


@dataclass
class Finding:
    file:           str
    line:           str
    severity:       str
    title:          str
    detail:         str
    fix:            str
    perspective_id: str = ""
    # ── Phase 2: 弁証法的トリアージ結果（triage.py が埋める） ─────
    # status は確定状態。"raw" は triage 未実施、"confirmed" / "dismissed" /
    # "inconclusive" は judge の判定結果。
    triage_status:    str = "raw"     # raw | confirmed | dismissed | inconclusive
    triage_confidence: float = 0.0    # judge の confidence (0.0-1.0)
    triage_reason:    str = ""        # judge の判定理由（短文）
    attacker_arg:     str = ""        # 攻撃側の主張要約
    defender_arg:     str = ""        # 防御側の反証要約
    poc:              str = ""        # 最小再現コード / payload / curl
    poc_kind:         str = ""        # http_request | curl | code | payload | none
    triage_error:     str = ""        # triage 自体の失敗理由（fail-open 用）


@dataclass
class GateStats:
    schema_rejected: int = 0
    file_missing:    int = 0
    duplicate:       int = 0
    safe_pattern:    int = 0

    @property
    def total(self) -> int:
        return self.schema_rejected + self.file_missing + self.duplicate + self.safe_pattern


# ──────── helpers ──────────────────────────────────────────────
def _normalize_path(p: str) -> str:
    """前置き ./ や Windows の \\ を吸収。比較は最終 path component ベースで行う。"""
    if not p:
        return ""
    p = p.replace("\\", "/").lstrip("./")
    return p


def file_in_diff(file: str, diff_files: Iterable[str]) -> bool:
    """LLM が報告したファイルが、実際の diff に含まれているか判定。
    ハルシネーション（diff に存在しないファイルを報告）を弾くゲート。
    """
    if not file:
        return False
    target = _normalize_path(file)
    for f in diff_files:
        nf = _normalize_path(f)
        if nf == target:
            return True
        # サブパス一致（"backend/app/x.py" vs "app/x.py"）も許容
        if nf.endswith("/" + target) or target.endswith("/" + nf):
            return True
    return False


def is_duplicate(f: Finding, validated: list[Finding]) -> bool:
    """同一 (file, line, title) は重複として除外。"""
    fp = _normalize_path(f.file)
    fl = str(f.line).strip()
    ft = (f.title or "").strip()
    for v in validated:
        if (
            _normalize_path(v.file) == fp
            and str(v.line).strip() == fl
            and (v.title or "").strip() == ft
        ):
            return True
    return False


def matches_known_safe_pattern(
    finding: Finding,
    diff_added_lines_by_file: dict[str, list[str]],
    safe_patterns_by_perspective: dict[str, list[re.Pattern]],
) -> bool:
    """diff の追加行（+ 行）に観点固有の安全パターンが見つかれば True。

    LLM が「dangerouslySetInnerHTML 使ってるからXSS！」のように一面的に判定したものを、
    周辺のコードに『FastAPI なら JSONResponse 使ってる / Pydantic でバリデート済み /
    defusedxml で XML パース』等の安全パターンが見えていれば一括で偽陽性扱いにする。
    """
    patterns = safe_patterns_by_perspective.get(finding.perspective_id, [])
    if not patterns:
        return False
    file_norm = _normalize_path(finding.file)
    # 完全一致 → サブパス一致の順で diff のキーを探す
    candidates = [
        diff_added_lines_by_file.get(file_norm),
    ]
    for k, v in diff_added_lines_by_file.items():
        nk = _normalize_path(k)
        if nk == file_norm:
            continue
        if nk.endswith("/" + file_norm) or file_norm.endswith("/" + nk):
            candidates.append(v)
    text_blocks = [b for b in candidates if b]
    if not text_blocks:
        return False
    text = "\n".join("\n".join(b) for b in text_blocks)
    return any(p.search(text) for p in patterns)


# ──────── main entry ───────────────────────────────────────────
def validate_findings(
    findings: list[Finding],
    diff_files: list[str],
    diff_added_lines_by_file: dict[str, list[str]],
    safe_patterns_by_perspective: dict[str, list[re.Pattern]],
) -> tuple[list[Finding], GateStats]:
    """4 ゲートを順に通し、通過したものだけ返す。"""
    stats = GateStats()
    validated: list[Finding] = []

    for f in findings:
        # ゲート1: スキーマ制約
        if f.severity not in VALID_SEVERITY:
            stats.schema_rejected += 1
            continue
        # ゲート2: ファイル存在チェック
        if not file_in_diff(f.file, diff_files):
            stats.file_missing += 1
            continue
        # ゲート3: 重複排除
        if is_duplicate(f, validated):
            stats.duplicate += 1
            continue
        # ゲート4: 観点固有 safe_pattern マッチ
        if matches_known_safe_pattern(f, diff_added_lines_by_file, safe_patterns_by_perspective):
            stats.safe_pattern += 1
            continue
        validated.append(f)

    return validated, stats
