# 利用者向け導入ガイド

既存リポジトリに `llm-security-scan` を導入してスキャン + (任意で) eval を回す手順。コピペで動くテンプレートを揃えてあるので、置換が必要な部分だけ自リポに合わせて書き換えてください。

> 想定読者: 既に動いているリポジトリのオーナー / セキュリティ担当 / DevOps。

---

## 0. 全体像

導入には 3 つのレベルがあります。**まず Level 1 だけ入れて動かし、必要に応じて 2 → 3 へ上げる**のが推奨。

| レベル | 内容 | 工数 |
|---|---|---|
| **L1: スキャンのみ** | PR diff に対する LLM スキャン + sticky comment。汎用 8 観点をそのまま使う | 5 分 |
| **L2: + 文脈** | `SECURITY-CONTEXT.md` でプロジェクト固有の認証 decorator や sanitizer を LLM に伝えて誤検知を減らす | 30 分 |
| **L3: + eval CI** | プロジェクト固有の eval ケースを書き、プロンプト変更で degrade した時に PR をブロック | 数時間〜継続 |

---

## L1: スキャン導入（最小構成）

### Step 1: API キーを Secret に登録

リポ Settings → Secrets and variables → Actions → New repository secret で **以下のいずれか 1 つ** を登録：

| 優先 | Secret | 用途 |
|---|---|---|
| 1（推奨） | `OPENAI_API_KEY` | OpenAI API キー |
| 2 | `GCP_SA_KEY` | GCP サービスアカウント JSON（Vertex AI） |
| 3 | `GEMINI_API_KEY` | Generative Language API キー |

3 つとも登録した場合は **OpenAI が優先** されます。

#### Vertex AI を使う場合の追加設定

Settings → Variables → New repository variable で：
- `GCP_PROJECT`: 自社の GCP プロジェクト ID（**必須**。未設定だと `CHANGE_ME` で API 呼び出しが失敗）
- `GCP_LOCATION`: default `us-central1`（任意）
- `LLM_MODEL`: default `gpt-4o-mini`（OpenAI 系のときのみ意味あり）

### Step 2: ワークフローを追加

リポに `.github/workflows/security-scan.yml` を作成：

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]      # 自リポの保護ブランチ名に合わせる

jobs:
  scan:
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v0.6.0
    secrets:
      OPENAI_API_KEY:  ${{ secrets.OPENAI_API_KEY }}
      GCP_SA_KEY:      ${{ secrets.GCP_SA_KEY }}
      GEMINI_API_KEY:  ${{ secrets.GEMINI_API_KEY }}
```

これだけ。次の PR から自動でスキャンが走り、結果が PR に sticky コメントで投稿されます。

### Step 3: 動作確認

- 何かファイルを変えた PR を作る
- Actions タブで `Security Scan` workflow が走ることを確認
- PR のコメント欄に `🛡️ LLM Security Scan` というタイトルのコメントが付くことを確認

→ ここまでが L1。これだけで 8 観点（XSS / SQL/NoSQL/コマンドインジェクション / 認証 / CSRF / 縦の権限昇格 / 横の権限不備 (IDOR) / Secrets / SSRF・Path Traversal）に対するベースラインのスキャンが効きます。

---

## L2: SECURITY-CONTEXT.md でプロジェクト固有の文脈を渡す

汎用 perspectives は「`@login_required` や `@authenticated` を見たら認証ガード」程度の汎用パターンしか知りません。**自社の内製 framework や独自命名は誤検知の温床** です。

### Step 1: 文脈ファイルを用意

リポ直下に `.github/security-scan-overrides/SECURITY-CONTEXT.md` を作成（ディレクトリ名は任意ですが、後の overrides と揃える意味でこの場所を推奨）：

```markdown
# このリポジトリの認証・認可・サニタイズ慣用

## 認証 / 認可
- `@authed` は当社内製 framework の認証 decorator。Cookie の JWT を verify する。
- `@require_user(role="admin")` は admin 権限ガード。decorator 無しの API はすべて public。
- `current_actor()` は認証済みユーザー（または None）を返す。`current_actor() is None` チェックがあれば認証は成立。

## SQL / NoSQL クエリ
- `db.q("SELECT ...", $1, $2)` は内製 ORM の placeholder バインド。SQLi 安全。
- `mongo.find({"user_id": uid})` の uid は ObjectId 型でバリデート済み（middleware で）。

## XSS サニタイズ
- `Render(template, data)` は HTML escape を強制。XSS 安全。
- `RawHtml(s)` は意図的に escape を切る関数。`s` が必ず内部生成 trusted 値であることを確認している箇所のみ使用。

## 既知の dev-only bypass
- `if env.DEV_AUTH_OFF:` は production 起動時に RuntimeError で die するガードが
  `auth/init.py:42` にある。dev でしか動かない。

## Secrets
- 環境変数: `os.getenv("X")` / `settings.X` 経由のみ。コード中の文字列リテラルに高エントロピー値があれば誤コミット疑い。
```

**書き方のコツ**:
- 短く具体的に。FAQ 形式 / 箇条書きで OK。
- 「これを見たら安全とみなしてよい」というポジティブな記述を中心に。
- マークダウン記法は使ってよい（LLM はパースする）。
- 数 KB 〜 10 KB が目安。長すぎるとトークン増。

### Step 2: ワークフローに `context_path` を追加

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  scan:
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v0.6.0
    with:
      context_path: .github/security-scan-overrides/SECURITY-CONTEXT.md
    secrets:
      OPENAI_API_KEY:  ${{ secrets.OPENAI_API_KEY }}
      GCP_SA_KEY:      ${{ secrets.GCP_SA_KEY }}
      GEMINI_API_KEY:  ${{ secrets.GEMINI_API_KEY }}
```

これで全 LLM 呼び出し（8 観点 × scan + Attacker / Defender / Judge × triage）の system prompt 末尾に文脈が注入されます。LLM は `@authed` を見たら認証ガードとして扱い、`Render()` を見たら XSS 安全と判断するようになります。

### (任意) Step 3: perspectives 自体の上書き

正規表現で機械的に弾きたい場合は、`code_safe_patterns` を追加した perspective YAML を `.github/security-scan-overrides/perspectives/authn.yml` に置く（観点 ID は `authn` / `csrf` / `authz_vertical` / `authz_horizontal` / `xss` / `injection` / `secrets` / `ssrf_path` から該当するものを選ぶ）：

```yaml
# .github/security-scan-overrides/perspectives/authn.yml
id: authn
name: 認証 (未認証アクセス・JWT 検証)
enabled: true
severity_weight: Critical
code_safe_patterns:
  # 汎用版から残したいものは明示
  - "@login_required"
  - "@authenticated"
  - "isAuthenticated"
  - "before_action\\s*:authenticate"
  # 自社固有を追加
  - "@authed"
  - "@require_user"
  - "current_actor\\(\\)"
prompt:
  # detect_patterns / safe_patterns / output_schema は汎用版をベースに自社語彙を追加
  detect_patterns: |
    ...
  safe_patterns: |
    ...
  output_schema: |
    ...
```

呼び出し側で `overrides_path` を指定：

```yaml
with:
  overrides_path: .github/security-scan-overrides
  context_path:   .github/security-scan-overrides/SECURITY-CONTEXT.md
```

`context_path` を省略した場合は `${overrides_path}/SECURITY-CONTEXT.md` が fallback で読まれます。

### (任意) 観点を絞る

特定観点が自リポでノイズだらけになった場合：

```yaml
with:
  perspectives_disabled: "secrets"        # CSV で複数指定可: "secrets,xss"
```

---

## L3: eval ケースを書いて degrade を CI ゲートで止める

「自社の `@authed` decorator がちゃんと安全マークされ続けるか」を CI で常時担保。プロンプト改善で過去のケースが degrade したら PR がブロックされます。

### Step 1: 最初の eval ケース 2 件を書く

`.github/security-scan-overrides/cases/001-authed-safe.diff`：

```diff
diff --git a/api/users.py b/api/users.py
index e69de29..a3b4c5d 100644
--- a/api/users.py
+++ b/api/users.py
@@ -1,5 +1,9 @@
 from fastapi import APIRouter
+from app.auth import authed

 router = APIRouter()

+@authed
+def get_user_profile(user_id: int):
+    return db.q("SELECT * FROM users WHERE id = $1", user_id)
```

これは `@authed` decorator + ORM placeholder で **safe**。authn 観点で confirmed が出てはいけない（誤検知）。

`.github/security-scan-overrides/cases/002-authed-missing.diff`：

```diff
diff --git a/api/users.py b/api/users.py
index e69de29..a3b4c5d 100644
--- a/api/users.py
+++ b/api/users.py
@@ -1,5 +1,8 @@
 from fastapi import APIRouter

 router = APIRouter()

+def delete_user(user_id: int):
+    db.q("DELETE FROM users WHERE id = $1", user_id)
+    return {"ok": True}
```

これは **decorator 無しの破壊的 API**。authn 観点で confirmed であるべき。

### Step 2: `expected.yml` を書く

`.github/security-scan-overrides/expected.yml`：

```yaml
- case: 001-authed-safe
  expect_verdict: dismissed
  expect_perspective: authn

- case: 002-authed-missing
  expect_verdict: confirmed
  expect_perspective: authn
  expect_min_confidence: 0.7
```

verdict のセマンティクス:
- `confirmed`: 該当観点に triage で confirmed が 1 件以上、かつ最高 confidence ≥ `expect_min_confidence`
- `dismissed`: 該当観点に confirmed が 1 件も無い（validator で弾かれた / LLM 検出なし / triage で dismissed どれも OK）
- `inconclusive`: 該当観点に inconclusive が 1 件以上

### Step 3: eval workflow を追加

`.github/workflows/security-eval.yml`：

```yaml
name: Security Eval
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  eval:
    uses: Zuck3-r/llm-security-scan/.github/workflows/eval.yml@v0.6.0
    with:
      cases_dir:    .github/security-scan-overrides/cases
      expected:     .github/security-scan-overrides/expected.yml
      context_path: .github/security-scan-overrides/SECURITY-CONTEXT.md
      overrides_path: .github/security-scan-overrides     # 任意
      # debate_rounds: 2  # inconclusive を救いたい場合 ON
    secrets:
      OPENAI_API_KEY:  ${{ secrets.OPENAI_API_KEY }}
      GCP_SA_KEY:      ${{ secrets.GCP_SA_KEY }}
      GEMINI_API_KEY:  ${{ secrets.GEMINI_API_KEY }}
```

### Step 4: branch protection で必須化

Settings → Branches → Add rule for `main`：
- Require status checks before merging を ON
- `eval` ジョブを Required に追加
- これで eval が落ちると main にマージできなくなる

### Step 5: ケースを増やす運用

CLAUDE.md §9 Step 2 に従い、**replay 由来でケースを増やす**のが最も実用的：

```bash
# ローカル
pip install pyyaml openai
gh auth login
export OPENAI_API_KEY=sk-...
git clone https://github.com/Zuck3-r/llm-security-scan
cd llm-security-scan
python replay.py --pr-range 1..50 --repo myorg/myrepo
# → replays/PR-*.json を眺めて、面白い verdict のものを cases/ に昇格
```

各観点（auth / xss / injection / secrets / ssrf_path）で confirmed/dismissed バランスよく **5〜10 ケース** あると、プロンプト改善時の retro-test として強力な武器になります。

---

## トラブルシュート

### スキャンが走らない
- `paths-ignore` に該当しない実コードのファイルが diff にあるか確認
- Actions タブで `Compute diff` ステップのログを見る → `skip_scan=true` だと PR にコメントが付かない

### 「No LLM provider credential available」エラー
- `OPENAI_API_KEY` / `GCP_SA_KEY` / `GEMINI_API_KEY` のいずれも未設定
- Settings → Secrets で登録（fork の PR では secrets が渡らないことがある点に注意）

### Vertex AI で 404 エラー
- `vars.GCP_PROJECT` が未設定で `CHANGE_ME` のまま呼んでいる → Settings → Variables で設定
- SA に Vertex AI User ロールが付いていない → IAM で付与

### 偽陽性ばかり出る
- `SECURITY-CONTEXT.md` で自社慣用を伝える（最大の効果）
- それでもダメなら `code_safe_patterns` に正規表現を追加（overrides の perspective YAML）
- 観点ごとオフ: `perspectives_disabled: "secrets"`

### eval CI が散発的に赤くなる
- `--no-retry` が ON になっていないか確認（default は retry-on）
- それでも頻発するなら `expect_min_confidence` を 0.7 → 0.6 に下げる
- もしくは LLM ブレ吸収のために `debate_rounds: 2` を ON

### コストが想定より高い
- `perspectives_disabled` で観点を減らす
- `triage_enabled: false` で triage を切る（精度は落ちる）
- `max_low_per_perspective: 1` で Low の triage 上限を絞る
- `debate_rounds: 1`（default）に戻す

---

## 参考: ファイル配置サンプル

```
your-repo/
├── .github/
│   ├── workflows/
│   │   ├── security-scan.yml          ← scan.yml を呼ぶ caller
│   │   └── security-eval.yml          ← eval.yml を呼ぶ caller (L3)
│   └── security-scan-overrides/
│       ├── SECURITY-CONTEXT.md        ← L2 の文脈ファイル
│       ├── perspectives/              ← (任意) perspective 上書き
│       │   └── authn.yml
│       ├── triage_prompts.yml         ← (任意) triage prompts 上書き
│       ├── cases/                     ← L3 の eval ケース
│       │   ├── 001-authed-safe.diff
│       │   └── 002-authed-missing.diff
│       └── expected.yml               ← L3 の期待値
└── ... (本来のソース)
```

---

## さらに

- 設計の詳細は本リポの [CLAUDE.md](../CLAUDE.md) を参照
- バグ報告 / フィードバックは Issue へ
