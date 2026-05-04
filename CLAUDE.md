# CLAUDE.md — LLM Security Scan 設計書

## 1. プロジェクト概要

GitHub Actions 上で動く LLM ベースのホワイトボックスセキュリティ診断ツール。
PR の diff に対して複数の診断観点（ハーネス）を並列実行し、弁証法的トリアージで偽陽性を排除したうえで、結果を PR コメントに投稿する。

**Reusable Workflow** として設計し、任意のリポジトリから `uses:` で呼び出せる。

元は Zuck3-r/Beacon リポジトリの `.github/security-scan/` として開発された Phase 1–3 実装を源流とし、Beacon 固有の依存を除去して汎用化したもの。


## 2. 設計原則

### 2.1 ハーネスエンジニアリング

Agent = Model + Harness。差別化要因はモデルではなくハーネスの設計にある。

- 失敗はプロンプトの注意書きではなく、スキーマ制約・イベントフック・検証ゲートとして実装する
- 1 ロール 1 API 呼び出し（W3 コンテキスト限界の緩和）
- perspectives も triage_prompts も YAML 化（コード変更なしでプロンプト編集可能）

### 2.2 最小介入

AIの推論余地を狭めずに、最小コストの仕組みで失敗を止める。

- system prompt は短く、英語（モデルの英語コーパスが厚く指示遵守率が高い）
- 出力指示で argument / reason は日本語（PR 読者が日本人のため）
- 指示を積み重ねると性能が下がるため、構造で制御する

### 2.3 fail-open

triage が失敗しても finding を消さない。inconclusive に倒す。
eval も replay もこの原則を尊重する。

### 2.4 トークン節約

- file filter: `.d.ts` / `test` / `stories` / `dist` / `build` / `coverage` / `__pycache__` を全除外
- diff が 30,000 文字を超えたらトリミング
- Low severity は観点ごとに上位 N 件のみ triage（rest は status=raw）


## 3. ディレクトリ構成

```
llm-security-scan/
├── CLAUDE.md                      ← この文書
├── README.md                      導入手順・利用例・eval スコア
├── src/
│   ├── engine.py                  実行エンジン (CLI: --diff / --output / --no-triage / etc.)
│   ├── triage.py                  弁証法的トリアージ (Attacker / Defender / Judge)
│   ├── validator.py               4 検証ゲート: schema / file-existence / dedup / safe_pattern
│   ├── reporter.py                Markdown レポート生成 (sticky PR comment)
│   └── providers.py               LLM プロバイダー切替 (OpenAI > Vertex AI > Gemini)
├── perspectives/                  汎用デフォルト観点 (10)
│   ├── xss.yml
│   ├── injection.yml
│   ├── authn.yml                  認証 (未認証アクセス・JWT 検証)
│   ├── csrf.yml                   CSRF
│   ├── authz_vertical.yml         縦の権限昇格
│   ├── authz_horizontal.yml       横の権限不備 / IDOR
│   ├── secrets.yml
│   ├── ssrf_path.yml
│   ├── business_logic.yml         ビジネスロジック不備 (検証欠落・状態遷移・冪等性)
│   └── file_inclusion.yml         ファイルインクルージョン / アップロード不備
├── triage_prompts.yml             Attacker / Defender / Judge のロール別プロンプト
├── .github/workflows/
│   └── scan.yml                   ★ reusable workflow (on: workflow_call)
├── evals/
│   ├── cases/                     手作り or replay 由来の diff
│   └── expected.yml               各 case の期待 verdict / confidence
├── replays/                       replay モードの出力先
├── replay.py                      過去 PR バックフィル CLI
└── eval.py                        eval harness CLI
```


## 4. アーキテクチャ

### 4.1 パイプライン

```
PR diff
  │
  ▼
engine.py
  ├── perspectives/*.yml をロード (enabled: true のみ)
  ├── 各ハーネスを asyncio.gather で並列 LLM 呼び出し
  ├── validator.py: 4 検証ゲート
  │   ├── ゲート1: スキーマ制約 (severity 値の妥当性)
  │   ├── ゲート2: ファイル存在チェック (ハルシネーション排除)
  │   ├── ゲート3: 重複排除 (file + line + title)
  │   └── ゲート4: code_safe_patterns の正規表現マッチ
  ├── triage.py: 弁証法的トリアージ (--no-triage で省略可)
  │   ├── Attacker: exploitable 前提で最小 PoC 構築
  │   ├── Defender: false positive 仮説で反証
  │   └── Judge: verdict (confirmed / dismissed / inconclusive) + confidence (0.0–1.0)
  └── reporter.py: Markdown レポート生成
        │
        ▼
    PR コメント (sticky)
```

### 4.2 判定 4 値のセマンティクス

| verdict | 意味 |
|---------|------|
| confirmed | Attacker の PoC が成立、Defender 反証弱い |
| dismissed | Defender 反証決定的、PoC 不成立 |
| inconclusive | 周辺コード不足で判定不能 |
| raw | triage 未実施（Low severity の上限超過分など） |

- confidence < 0.6 の dismissed は折り畳まず人手レビューに残す


## 5. Reusable Workflow

### 5.1 呼び出し側（利用リポジトリ）

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  pull_request:
    branches: [main]
jobs:
  scan:
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v1
    with:
      overrides_path: .github/security-scan-overrides   # 任意
      perspectives_disabled: ""                          # 任意 (e.g. "secrets,xss")
    secrets:
      OPENAI_API_KEY:  ${{ secrets.OPENAI_API_KEY }}
      GCP_SA_KEY:      ${{ secrets.GCP_SA_KEY }}
      GEMINI_API_KEY:  ${{ secrets.GEMINI_API_KEY }}
```

### 5.2 overrides_path の仕組み

プロジェクト固有の安全パターンや perspectives を上書き・追加する仕組み。

```
.github/security-scan-overrides/
├── perspectives/
│   ├── auth.yml          # 汎用版を上書き（code_safe_patterns にプロジェクト固有のものを追加）
│   └── custom.yml        # プロジェクト独自の観点を追加
└── triage_prompts.yml    # triage プロンプトを上書き（任意）
```

マージ戦略:
- perspectives: overrides 側に同名 yml があれば上書き。新規 yml は追加
- triage_prompts.yml: overrides 側にあれば全体上書き
- 汎用 perspectives には Beacon 固有名詞を残さない

### 5.3 scan.yml の inputs

| input | type | default | 説明 |
|-------|------|---------|------|
| overrides_path | string | "" | プロジェクト固有の perspectives / prompts |
| perspectives_disabled | string | "" | 無効にする perspective id (comma 区切り) |
| scan_targets | string | "*.py *.ts *.tsx *.js *.jsx" | diff 対象のファイルパターン |
| max_low_per_perspective | number | 3 | Low severity の triage 上限 |
| triage_enabled | boolean | true | triage を有効にするか |
| debate_rounds | number | 1 | Multi-round debate のラウンド数 (将来用) |


## 6. LLM プロバイダー

優先順: OpenAI > Vertex AI > Gemini (Generative Language API)

| provider | 認証 | モデルデフォルト |
|----------|------|------------------|
| OpenAI | `OPENAI_API_KEY` | gpt-4o-mini |
| Vertex AI | `GCP_SA_KEY` (SA JSON) + ADC | gemini-2.0-flash |
| Gemini | `GEMINI_API_KEY` | gemini-2.0-flash |

`LLM_PROVIDER` 環境変数で明示指定可能。`LLM_MODEL` でモデルを上書き可能。
429 / ResourceExhausted は指数バックオフで 3 回までリトライ。


## 7. perspectives YAML スキーマ

```yaml
id: string              # 一意の識別子
name: string            # 表示名
enabled: boolean        # true/false で ON/OFF
severity_weight: string # デフォルト重要度 (Critical|High|Medium|Low)

# validator.py が使う正規表現（コード側の安全パターン）
code_safe_patterns:
  - "regex_pattern_1"
  - "regex_pattern_2"

# LLM に渡すプロンプト（3 セクション構成）
prompt:
  detect_patterns: |
    ...（何を見つけるか）
  safe_patterns: |
    ...（何を安全とみなすか。LLM への指示側）
  output_schema: |
    ...（JSON 出力形式の強制）
```

`code_safe_patterns` はプロンプトの `safe_patterns` と二重化。
LLM が safe_patterns を無視した場合（W1 訓練バイアス）のセーフティネット。


## 8. triage_prompts.yml

```yaml
attacker:
  system: |
    (英語) 攻撃側のロール指示
  output_schema: |
    (JSON スキーマ + 日本語指定)

defender:
  system: |
    (英語) 防御側のロール指示
  output_schema: |
    (JSON スキーマ + 日本語指定)

judge:
  system: |
    (英語) 判定者のロール指示。confidence 0.0-1.0 のガイドライン含む
  output_schema: |
    (JSON スキーマ + 日本語指定)
```

フォールバック: YAML 読込失敗時は triage.py 内の英語ハードコード版に切り替え。


## 9. 実装フェーズ

### Phase 1–3（完了。Beacon から移植済み）

- Phase 1: ハーネス骨格 + xss / injection 観点 + 4 検証ゲート
- Phase 2: 弁証法的トリアージ + PoC 構築 + YAML 化 + 英語 system 化 + file filter 厳格化
- Phase 3: auth / secrets / ssrf_path 観点追加 + Judge confidence (0.0–1.0) + 低確信 dismissed の救済
- Phase 4 (post v0.5): auth.yml を authn / csrf / authz_vertical / authz_horizontal の 4 観点に分割（責務明確化・PR レポートのカテゴリ独立化・領域固有 safe_pattern の精度向上）

### Step 0: Beacon からの移植 + 汎用化（このリポジトリの初期作業）

- `.github/security-scan/*` をルートに昇格して `src/` 構造に再編
- Beacon 固有の安全パターン（`_dev_bypass_enabled` 等）を除去
- scan.yml を `on: workflow_call` 化
- overrides_path マージロジック実装
- タグ v0.1.0

### Step 1: Replay モード（feat/replay）

**なぜ最優先**: eval ケースを手書きするより、過去 PR を回して目視で選ぶ方が速い。

```bash
python replay.py --pr 42
python replay.py --pr-range 1..100
```

出力: `replays/PR-<n>.json`
```json
{
  "pr_number": 42,
  "title": "...",
  "merged_at": "...",
  "diff_stats": { "files": 5, "additions": 230, "deletions": 12 },
  "findings": [],
  "triage": { "confirmed": 1, "dismissed": 2, "inconclusive": 0 },
  "tokens": { "scan_in": 1234, "scan_out": 567, "triage_in": 0, "triage_out": 0 }
}
```

workflow_dispatch ジョブも併設（artifact として replays/*.json をアップロード）。

### Step 2: Eval harness（feat/evals）

```
evals/
├── cases/<id>-<title>.diff
└── expected.yml
```

```yaml
# expected.yml
- case: 001-xss-real
  expect_verdict: confirmed
  expect_perspective: xss
  expect_min_confidence: 0.7
- case: 002-xss-fp
  expect_verdict: dismissed
  expect_perspective: xss
```

```bash
python eval.py  # → 全 case を engine.py に流して expected.yml と突合、不一致で exit 1
```

CI: PR で eval が落ちたらマージ不可。

ワークフロー: replays/ から「答案確定」と判断したものを cases/ にコピーして expected.yml にエントリ追加。

### Step 3: Cross-PR triage cache（feat/cache）

**eval が安定してから実装**（プロンプトが揺れている期間にキャッシュを焼くと古い verdict で汚染される）。

- キー: `sha256(perspective_id + file + line + title + diff_hunk_around)`
- 値: `{ verdict, confidence, attacker_arg, defender_arg, poc, ts, prompt_version }`
- 保存先: GitHub Actions cache (`actions/cache@v4`) または Artifacts
- 無効化: `triage_prompts.yml` の hash か `prompt_version` 文字列が変わったら全 miss
- TTL: 30–90 日

### Step 4: Multi-round debate（feat/multi-round-debate）

**実装前にユーザーに「inconclusive のみ二段構え」設計で OK か確認すること。**

- 現状 1 ラウンド: Attacker → Defender → Judge
- Multi-round: Attacker → Defender → Attacker(反論 v2) → Defender(再反証) → Judge
- inconclusive 判定のみに追加ラウンドを当てる（confirmed / dismissed には適用しない、コスト最適化）
- `--debate-rounds 2`（デフォルト 1 = 現状互換）
- triage_prompts.yml に `attacker_rebut` / `defender_rebut` ロールを追加


## 10. やらないこと

- 隔離環境での PoC 実投擲（dynamic verification）
- テストファイルのスキャン（file filter で除外済み）

### 観点追加の方針

観点は領域ごとに必要なだけ追加する。境界が曖昧な複合観点は分割して責務を明確化する。
追加・分割時のルール:

- 1 観点 = 1 つの責務領域（例: authn と authz_vertical は別観点）
- `code_safe_patterns` は当該観点に固有のマーカーのみを置く（汎用すぎる regex は別観点の真の脆弱性まで吸収する）
- prompt の `safe_patterns` 末尾で「他観点の責務との境界」を明示（重複検出は validator のゲート3 dedup で吸収されるが、prompt 側でも切り分ける）
- 追加に伴い更新するもの: README の観点表、CONSUMER_SETUP の例示観点 id、evals/expected.yml のコメント


## 11. 開発ブランチ運用

- main は常にグリーン
- feature ブランチ命名: `feat/replay`, `feat/evals`, `feat/cache`, `feat/multi-round-debate`
- 各機能は 1 PR にまとめる
- eval が pass することを各 PR の必須条件とする（self-CI）

### コミットメッセージ規約

```
feat: 機能追加
fix: バグ修正
refactor: リファクタリング
docs: ドキュメントのみ
chore: CI / 依存更新等
```


## 12. LLM の構造的弱点と対策マッピング

（Ricerca Security の研究に基づく）

| 弱点 | 内容 | このツールでの対策 |
|------|------|-------------------|
| W1 訓練バイアス | パターンへの過剰適合 | code_safe_patterns のコード側チェック (validator.py ゲート4) |
| W2 観測の過信 | 仮説を検証なしに採用 | ファイル存在チェック (ゲート2)、スキーマ制約 (ゲート1)、弁証法的トリアージ |
| W3 コンテキスト限界 | 長い実行で証拠を喪失 | 1 ロール 1 API 呼び出し。独立したコンテキストで動作 |
| W4 計画固執 | 非効率な計画への固執 | 現状は 1 ハーネス 1 呼び出しで該当しない。Multi-round debate で対処予定 |


## 13. ログ・出力方針

- engine.py は標準出力にスキャン結果を書かない
- レポートは `--output` で指定された Markdown ファイルだけ
- stdout はデバッグログのみ（CI のログに出る）
- replay / eval の結果は JSON ファイルとして保存
