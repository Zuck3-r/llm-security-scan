# 🛡️ LLM Security Scan

GitHub Actions Reusable Workflow として動く、LLM ベースのホワイトボックスセキュリティ診断ツール。

PR の diff に対して 5 つの診断観点で並列スキャンし、弁証法的トリアージ（Attacker / Defender / Judge）で偽陽性を排除したうえで、結果を PR コメントに投稿する。

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
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v1
    with:
      overrides_path: ""                # プロジェクト固有の設定がある場合に指定
      perspectives_disabled: ""         # 無効にする観点 (e.g. "secrets,xss")
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

### 3. PR を作成

以上。PR を作れば自動でスキャンが走り、結果が PR コメントに投稿される。


## 診断観点

| # | 観点 | デフォルト重要度 |
|---|------|------------------|
| 1 | XSS (クロスサイトスクリプティング) | High |
| 2 | インジェクション (SQLi / NoSQLi / コマンド) | Critical |
| 3 | 認証・認可 (Authn / Authz / IDOR) | Critical |
| 4 | 秘匿情報の混入 / 漏洩 | Critical |
| 5 | SSRF / Path Traversal | High |


## 弁証法的トリアージ

各 finding に対して 3 つの独立した LLM ロールが判定:

1. **Attacker**: exploitable 前提で最小 PoC を構築
2. **Defender**: false positive 仮説で反証
3. **Judge**: 両者を読み confirmed / dismissed / inconclusive + confidence (0.0–1.0) を判定

`--no-triage` で省略可能（Phase 1 互換動作）。


## プロジェクト固有のカスタマイズ

`overrides_path` にプロジェクト固有の perspectives / triage_prompts を置くと、汎用デフォルトを上書き・追加できる。

```
.github/security-scan-overrides/
├── perspectives/
│   ├── auth.yml          # code_safe_patterns にプロジェクト固有のものを追加
│   └── custom.yml        # 独自の観点を追加
└── triage_prompts.yml    # triage プロンプトを上書き
```


## コスト目安

| モデル | 1PR (triage あり) | 月 100 PR |
|--------|------------------|-----------|
| gpt-4o-mini | ~$0.15 | ~$15 |
| gemini-2.0-flash | ~$0.08 | ~$8 |

※ 5 観点 + triage の場合。`perspectives_disabled` で観点を減らすと比例して減少。


## Eval スコア

> (eval harness 実装後に更新)

| case | expected | actual | confidence | pass |
|------|----------|--------|------------|------|
| — | — | — | — | — |


## 設計思想

[ハーネスエンジニアリング](https://ricsec.co.jp/) の考え方に基づく:
- LLM の失敗をプロンプトではなく構造（検証ゲート・スキーマ制約）で止める
- 最小介入: AI の推論余地を狭めない
- fail-open: triage 失敗で finding を消さない

詳細は [CLAUDE.md](./CLAUDE.md) を参照。
