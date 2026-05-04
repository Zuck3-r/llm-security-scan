# 🛡️ LLM Security Scan

GitHub Actions Reusable Workflow として動く、LLM ベースのホワイトボックスセキュリティ診断ツール。

PR の diff に対して 10 の診断観点で並列スキャンし、弁証法的トリアージ（Attacker / Defender / Judge）で偽陽性を排除したうえで、結果を PR コメントに投稿する。

> **既存リポへの導入手順は [docs/CONSUMER_SETUP.md](./docs/CONSUMER_SETUP.md)** を参照。Level 1（最小スキャン）/ Level 2（SECURITY-CONTEXT で文脈注入）/ Level 3（eval CI で degrade ガード）の 3 段階で段階的に上げられます。

## クイックスタート

### 1. リポジトリに workflow を追加

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  pull_request:
    branches: [main]
jobs:
  scan:
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v0.7.0
    with:
      overrides_path: ""                # プロジェクト固有の設定がある場合に指定
      perspectives_disabled: ""         # 無効にする観点 (e.g. "secrets,xss")
      # context_path: .github/security-scan-overrides/SECURITY-CONTEXT.md
      # scan_exclude_extensions: "md,markdown,..."   # default で十分なことが多い
      # scan_extra_excludes: ":(exclude)docs/** :(exclude)scripts/**"
      # debate_rounds: 2                # inconclusive を救いたいなら 2 (Step 4 opt-in)
    secrets:
      OPENAI_API_KEY:  ${{ secrets.OPENAI_API_KEY }}
      GCP_SA_KEY:      ${{ secrets.GCP_SA_KEY }}
      GEMINI_API_KEY:  ${{ secrets.GEMINI_API_KEY }}
```

### 2. Secrets を登録

リポジトリの Settings → Secrets and variables → Actions で以下のいずれかを登録:

| 優先度 | Secret | 説明 |
|--------|--------|------|
| 1 (推奨) | `OPENAI_API_KEY` | OpenAI API キー |
| 2 | `GCP_SA_KEY` | GCP サービスアカウント JSON (Vertex AI) |
| 3 | `GEMINI_API_KEY` | Generative Language API キー |

**Vertex AI を使う場合のみ**: Settings → Variables に `GCP_PROJECT` を追加して GCP プロジェクト ID を設定してください（未設定だと `CHANGE_ME` で API 呼び出しが失敗します）。`GCP_LOCATION` (default: `us-central1`) と `LLM_MODEL` (default: `gpt-4o-mini`) も同様に Variables で上書き可能です。

### 3. PR を作成

以上。PR を作れば自動でスキャンが走り、結果が PR コメントに投稿される。


## 診断観点

| # | id | 観点 | デフォルト重要度 |
|---|----|------|------------------|
| 1 | `xss` | XSS (クロスサイトスクリプティング) | High |
| 2 | `injection` | インジェクション (SQLi / NoSQLi / コマンド) | Critical |
| 3 | `authn` | 認証 (未認証アクセス・JWT 検証) | Critical |
| 4 | `csrf` | CSRF (Cross-Site Request Forgery) | High |
| 5 | `authz_vertical` | 権限昇格 (縦) | Critical |
| 6 | `authz_horizontal` | 権限不備 (横 / IDOR / BOLA) | Critical |
| 7 | `secrets` | 秘匿情報の混入 / 漏洩 | Critical |
| 8 | `ssrf_path` | SSRF / Path Traversal | High |
| 9 | `business_logic` | ビジネスロジック不備 (検証欠落・状態遷移・冪等性) | High |
| 10 | `file_inclusion` | ファイルインクルージョン / アップロード不備 | High |

> **Migration**: v0.5 まで `auth` 1 観点で扱っていた領域は、v0.6 以降 `authn` / `csrf` / `authz_vertical` / `authz_horizontal` の 4 観点に分割された。`overrides_path/perspectives/auth.yml` を持つプロジェクトは、内容を上記 4 観点それぞれに分配するか、当面は `id: auth` のまま新規 perspective として残してもよい (overrides の追加観点として読み込まれる)。


## 弁証法的トリアージ

各 finding に対して 3 つの独立した LLM ロールが判定:

1. **Attacker**: exploitable 前提で最小 PoC を構築
2. **Defender**: false positive 仮説で反証
3. **Judge**: 両者を読み confirmed / dismissed / inconclusive + confidence (0.0–1.0) を判定

`--no-triage` で省略可能（Phase 1 互換動作）。

### Multi-round debate (Step 4, opt-in)

Round 1 で `inconclusive` になった finding に対してだけ、もう 1 ラウンド (Attacker_rebut → Defender_rebut → Judge 再判定) を回して `confirmed` か `dismissed` に倒すことを試みる。

- `with: debate_rounds: 2` で有効化 (default は `1` = 互換動作)
- **`confirmed` / `dismissed` には適用しない** (コスト最適化)
- 効果: Round 1 では片方の主張が弱くて判定不能だったケースが、相手の反論を踏まえた強い PoC v2 / 強い反証で確定できる
- 救えないケースは Round 2 後も `inconclusive` のまま (fail-open: 人間の最終判定に残す)
- コスト影響: inconclusive 1 件あたり LLM 呼び出し +3 回。inconclusive 比率 20% なら全体トークン約 +10%

Round 2 の追加情報は finding に格納される:

| フィールド | 内容 |
|---|---|
| `attacker_arg_rebut` | Round 2 で Attacker が出した反論 |
| `defender_arg_rebut` | Round 2 で Defender が出した再反証 |
| `triage_rounds` | 1 (Round 2 未実施) または 2 (Round 2 走った) |


## プロジェクト固有のカスタマイズ

汎用デフォルトを caller リポジトリ側で上書き・拡張する仕組みは 2 種類あります。

### (A) `SECURITY-CONTEXT.md` — LLM へ意味的な文脈を渡す

内製 framework の認証 decorator 名・独自 sanitizer・dev-only bypass のガード条件など「文字列マッチでは表現しきれない意味」を LLM に伝える markdown ファイル。指定すると **scan の 10 観点と triage の Attacker / Defender / Judge すべての system prompt 末尾**に注入されます。

```yaml
with:
  overrides_path: .github/security-scan-overrides
  context_path:   .github/security-scan-overrides/SECURITY-CONTEXT.md
```

`context_path` が空のとき `${overrides_path}/SECURITY-CONTEXT.md` が fallback として読まれます。両方無ければ no-op。

例: `.github/security-scan-overrides/SECURITY-CONTEXT.md`

```markdown
# このリポジトリの認証・認可の慣用

## 認証 decorator
- `@authed` は当社内製 framework の認証 decorator。Cookie の JWT を検証する。
- `@require_user(role="admin")` は admin 権限ガード。

## 安全なクエリ経路
- `db.q("SELECT ...", $1, $2)` は内製 ORM の placeholder バインド。SQLi 安全。

## 既知の dev-only bypass
- `if env.DEV_AUTH_OFF:` は production 起動時に RuntimeError で死ぬガードが
  auth/init.py:42 にある。dev でしか動かない。
```

LLM は「`@authed` を見たら認証ガード扱い」「`db.q` の placeholder は安全」と判定できるようになります。文脈は全 LLM 呼び出しで共通なので prompt cache の prefix として効き、コストはほぼ増えません。

### (B) `overrides_path` — perspectives / triage_prompts を上書き

正規表現の `code_safe_patterns` を増やしたい / 独自観点を 1 ファイルで追加したい場合：

```
.github/security-scan-overrides/
├── SECURITY-CONTEXT.md   # (A) — LLM への意味的な文脈
├── perspectives/
│   ├── auth.yml          # code_safe_patterns にプロジェクト固有の正規表現を追加
│   └── payment.yml       # 独自の観点を追加 (ファイル名は任意)
└── triage_prompts.yml    # triage プロンプトを丸ごと上書き
```

マージ規則: 同名 yml は overlay で上書き、新規 yml は追加観点として読み込み、`triage_prompts.yml` は丸ごと差し替え。

### 使い分け

- 「`@authed` という decorator が認証ガード」みたいな**意味的な情報**は (A)
- 「正規表現で機械的に弾きたい / 観点を 1 つ増やしたい」は (B)
- 両方併用 OK


## スキャン対象の絞り込み

default は **fail-safe なブラックリスト方式**: ランタイムに載らないファイル (md / json / lock / 画像 等) だけを除外し、それ以外は全部スキャンします。Go / Ruby / Java / PHP 等の言語は何も設定しなくても対象に入ります。

| input | 用途 | default |
|---|---|---|
| `scan_exclude_extensions` | 除外する拡張子 (CSV, ドット無し) | `md,markdown,txt,rst,yml,yaml,json,jsonc,lock,toml,cfg,ini,gitignore,dockerignore,editorconfig,svg,png,jpg,jpeg,gif,webp,ico,pdf,csv,tsv` |
| `scan_extra_excludes` | 追加の git pathspec (空白区切り) | 空 |

注意:
- `.env` は意図的に除外していません（誤コミットされた secrets を検出する観点で価値が高いため）
- `tests/`, `dist/`, `build/`, `node_modules/`, `vendor/`, ロックファイル等の path-based 除外は固定で内蔵
- diff が 30,000 文字を超えると engine 側でトリミングされます (`engine.py:DIFF_MAX_CHARS`)


## コスト目安

| モデル | 1PR (triage あり) | 月 100 PR |
|--------|------------------|-----------|
| gpt-4o-mini | ~$0.15 | ~$15 |
| gemini-2.0-flash | ~$0.08 | ~$8 |

※ 10 観点 + triage の場合。`perspectives_disabled` で観点を減らすと比例して減少。


## Replay モード (Step 1)

過去 PR をまとめてスキャンして JSON で記録するモード。eval ケースを手書きするより、過去 PR を回して目視で「答案確定」できたものを `evals/cases/` に昇格させるためのフィードバックループの起点になる。

### ローカル実行

```bash
pip install -r requirements.txt
gh auth login                         # GitHub CLI で認証
export OPENAI_API_KEY=sk-...

python replay.py --pr 42                       # 単発
python replay.py --pr-range 1..100             # 範囲
python replay.py --pr 42 --repo owner/name     # 別リポを対象に
python replay.py --pr 42 --context SECURITY-CONTEXT.md   # 文脈を注入して走らせる
python replay.py --pr-range 1..50 --no-triage  # コスト節約モード
```

出力: `replays/PR-<n>.json`

```json
{
  "pr_number": 42,
  "title":     "...",
  "merged_at": "2026-04-15T03:21:00Z",
  "diff_stats": { "files": 5, "additions": 230, "deletions": 12 },
  "findings":   [ /* 検証ゲート通過後・トリアージ済み */ ],
  "triage":     { "confirmed": 1, "dismissed": 2, "inconclusive": 0, "raw": 0 },
  "tokens":     { "scan_in": 1234, "scan_out": 567, "triage_in": 890, "triage_out": 123 }
}
```

### CI 経由 (workflow_dispatch)

`.github/workflows/replay.yml` を Run workflow から起動。`pr` または `pr_range` を入力すると `replays/*.json` が artifact としてアップロードされる。

## Eval (Step 2)

プロンプト編集や perspective 追加で**過去に正しく判定できていたケースが落ちていないか** を CI で担保する仕組み。`evals/cases/*.diff` を `engine.scan_diff()` に流し、`evals/expected.yml` の期待値と突合する。

### 追加方法

1. `evals/cases/<id>-<title>.diff` を置く（手書き or replay の出力から流用）
2. `evals/expected.yml` に 1 エントリ追加：

```yaml
- case:                  003-sqli-real
  expect_verdict:        confirmed         # confirmed | dismissed | inconclusive
  expect_perspective:    injection
  expect_min_confidence: 0.7               # confirmed のときのみ意味あり
```

判定セマンティクス：

| `expect_verdict` | pass 条件 |
|---|---|
| `confirmed` | 該当観点に `triage_status=confirmed` の finding が >=1、最高 confidence が `expect_min_confidence` 以上 |
| `dismissed` | 該当観点に `triage_status=confirmed` の finding が 1 件も無い（validator で弾かれた / LLM 検出なし / triage が dismissed 化、いずれも OK） |
| `inconclusive` | 該当観点に `triage_status=inconclusive` の finding が >=1 |

### ローカル実行

```bash
python eval.py                              # 通常実行 (retry あり)
python eval.py --verbose                    # attempt ごとのログを stderr に
python eval.py --no-retry                   # retry を無効化 (デバッグ用)
python eval.py --context SECURITY-CONTEXT.md
```

出力例：

```
case          expected                   actual                att  status
001-xss-real  confirmed/xss/conf>=0.7    C=1 D=0 I=0 (total=1)   1  PASS
002-xss-fp    dismissed/xss              C=0 D=0 I=0 (total=0)   1  PASS

OK 2/2 cases passed (0 retries used)
```

### Retry ポリシー

LLM は temperature=0 でも完全には決定的ではないため、不一致 case は **1 回だけ retry** する（Run 1 fail → Run 2 pass なら `PASS_RETRY` 扱い）。2 連続不一致なら本物の degrade として `FAIL`。`--no-retry` で無効化可能（デバッグ時）。

### CI（このリポジトリ自身）

`.github/workflows/eval-self.yml` が PR と main push の両方で実行され、失敗するとマージできない。本リポの `evals/cases/` をベースラインとして、プロンプト改変による degrade を検出する。

### CI（利用者リポジトリ向け）

`.github/workflows/eval.yml` は `workflow_call` 化されており、利用者は自リポの eval ケースに対して実行できる。詳細は **[docs/CONSUMER_SETUP.md § Level 3](./docs/CONSUMER_SETUP.md#l3-eval-ケースを書いて-degrade-を-ci-ゲートで止める)** を参照。

```yaml
# 利用者側: .github/workflows/security-eval.yml
name: Security Eval
on:
  pull_request:
    branches: [main]
jobs:
  eval:
    uses: Zuck3-r/llm-security-scan/.github/workflows/eval.yml@v0.7.0
    with:
      cases_dir:    .github/security-scan-overrides/cases
      expected:     .github/security-scan-overrides/expected.yml
      context_path: .github/security-scan-overrides/SECURITY-CONTEXT.md
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```


## 設計思想

[ハーネスエンジニアリング](https://ricsec.co.jp/) の考え方に基づく:
- LLM の失敗をプロンプトではなく構造（検証ゲート・スキーマ制約）で止める
- 最小介入: AI の推論余地を狭めない
- fail-open: triage 失敗で finding を消さない

詳細は [CLAUDE.md](./CLAUDE.md) を参照。
