# SECURITY-CONTEXT.md 作成ガイド

`SECURITY-CONTEXT.md` は、`llm-security-scan` の LLM スキャナに **「diff だけを読んでも分からないリポジトリ固有の事情」** を伝えるためのドキュメントです。これを置くと scan 8 観点 + triage 3 ロール全ての system prompt 末尾に注入され、誤検出 / 見逃しの両方を大きく減らせます。

このガイドは「何を書くべきか」と「AI に下書きを作らせるためのコピペ用 prompt」を提供します。

---

## なぜ必要か (3 つの典型例)

スキャナは **PR diff だけ** を読みます。そのため以下のような「リポジトリ全体を見て初めて分かること」を知りません:

| シナリオ | 起きる失敗 |
|---|---|
| 内製 framework の `@authed` が認証 decorator | `@login_required` を知らないので「認証ガードが無い」と誤検出 |
| 公開掲示板アプリで「他人の投稿にコメント可」が仕様 | 「所有チェック無し = IDOR」と誤検出 |
| Rails の `ApplicationController` 継承で CSRF 防御が default で effective | 「CSRF 検証コードが見えない」と誤検出 |
| 共通 middleware (`app.use(...)`) で全ルートが保護されている | 個別 route の diff には防御コードが無いので「無防備」と誤検出 |

逆方向の見逃し (broken な自作 middleware を「対策済み」と誤判定するケース) を完全に消すことはできませんが、SECURITY-CONTEXT.md で「自作 X が真の防御」と宣言してあれば LLM の判定はその範囲に限定されます。

---

## 何を書くか — 抽出すべき項目

| カテゴリ | 書く内容 |
|---|---|
| **認証 (Authn)** | 認証 middleware / decorator の名前 (内製含む)、public ルート判別法、JWT vs session の使い分け |
| **認可 (Authz)** | role 表現 (`current_user.role` / `abilities` 等)、admin 判定の慣用名、所有チェックの慣用パターン (ORM scope / Pundit / CanCanCan / Casbin 等) |
| **CSRF** | framework default を使っているか / 自社 middleware か / CSRF 不要な経路 (Bearer 認証 API 等) |
| **XSS / 出力エスケープ** | テンプレートエンジン、生出力に使う関数名、内製 sanitizer 名 |
| **設計意図 (最重要)** | public-by-design vs private-by-design、「他人のリソースを読み書きできる」が仕様な経路、意図的に認証を外している経路 |
| **dev-only bypass** | `if env.DEV_AUTH_OFF:` 等、production で死ぬ guard と同居しているか |
| **命名規約** | 「これを呼んでいたら安全」と言える内製関数 / decorator 名 (regex 化候補) |

---

## 推奨ワークフロー: AI に下書きを作らせる

リポジトリ全体を人間が網羅的に読むのは大変なので、まず AI に下書きを作らせ、人間がレビュー・調整するのが現実的です。

### Step 1: 以下の prompt をコピー

````markdown
あなたはセキュリティレビューアです。これから渡すリポジトリ全体を読んで、
LLM ベースのセキュリティスキャナ (llm-security-scan) に渡す
SECURITY-CONTEXT.md を作成してください。

このドキュメントの目的: スキャナは PR diff だけを読むため、
リポジトリ全体の設計慣用や framework 共通設定、アプリの設計意図を知りません。
SECURITY-CONTEXT.md は「diff だけを見ると誤検出 (false positive) や
見逃し (false negative) になりそうな、リポジトリ固有の事情」を
簡潔に伝える文書です。

## 抽出すべき項目

1. 認証 (Authentication)
   - 認証 middleware / decorator / guard の名前 (内製名を含む)
     例: `@authed`, `requireLogin`, `before_action :authenticate_user!`
   - 認証されない (public) ルートの命名規約や置き場所
   - JWT / session / cookie の使い分け
   - 認証が必須 vs 任意 のエンドポイント区分

2. 認可 (Authorization)
   - role / permission の表現 (例: `current_user.role`, `current_user.admin?`,
     `abilities`, RBAC の階層構造)
   - admin 判定の慣用 (内製 decorator / 関数名)
   - 所有チェックの慣用パターン (ORM scope / Pundit / CanCanCan / Casbin / 内製ヘルパ)
   - mass-assignment 防御 (Strong Parameters / Pydantic exclude / DTO 層)

3. CSRF
   - framework default を使っているか (Rails `protect_from_forgery` /
     Django `CsrfViewMiddleware` / Laravel `VerifyCsrfToken`)
   - 自社 middleware を使っているか / そのファイルパス / 検証ロジックの正当性
   - CSRF が不要な経路 (純 JSON API + Bearer 認証 等)

4. XSS / 出力エスケープ
   - テンプレートエンジン (EJS / ERB / Twig / Jinja2 / JSX 等)
   - default で auto-escape か、生出力に使う構文 (例: EJS `<%- %>`, Jinja2 `|safe`)
   - 内製 sanitizer の名前 (例: `sanitizeHtml()`, `Render()`)

5. 設計意図 (これが最重要 — false positive を最も削減する)
   - public-by-design vs private-by-design
     例: 「全投稿は全ログインユーザに公開 (公開掲示板モデル)」
     例: 「メッセージは送受信者間のみ (private DM モデル)」
   - 「他人のリソースを読み書きできる」が仕様な経路
     例: 「コメントは誰でも書ける (但し削除は所有者のみ)」
   - 意図的に認証を外している経路
     例: health check / public landing / OAuth callback

6. dev-only bypass / feature flag
   - `if env.DEV_AUTH_OFF:` / `if Rails.env.development?` 等のガード
   - production で死ぬ guard が同居しているか (例: 起動時に RuntimeError)

7. 命名規約 (regex 化して code_safe_patterns に入れる候補)
   - 内製 decorator / 関数名で「これを呼んでいたら安全」と言えるもの
     例: `@authed`, `db.q()`, `current_actor()`, `safe_render()`

## 出力ルール

- markdown 形式。各項目は箇条書きで 2-5 行程度に短くまとめる
- 該当が無い項目は省略してよい (項目見出しごと省略)
- リポジトリから読み取れない / 不確かな点は「(推測)」を付ける
- コード抜粋は 3-5 行程度に留める。長い貼り付けはしない
- 出力は SECURITY-CONTEXT.md の中身そのもの。前置きや説明文は不要

## 出力例 (構造の参考)

```markdown
# このリポジトリのセキュリティ文脈

## 認証
- `requireLogin` (src/middleware/auth.js) が session.user の存在を見る認証 middleware
- public ルート: `/`, `/auth/*`, `/health`
- session-based (cookie 認証)。JWT は使っていない

## 認可
- `current_user.role` は `'admin'` または `'member'` の 2 値
- admin 判定: `requireAdmin` middleware (src/middleware/auth.js)
- 所有チェック: 各 controller 内で `record.user_id === req.session.user.id` を直接比較

## CSRF
- 自作 middleware (src/middleware/csrf.js) を `app.use()` で全ルートに attach
- session に保存した token と body._csrf を timing-safe 比較

## XSS
- EJS テンプレート。`<%= %>` (auto-escape) を基本とし、生出力 `<%- %>` は使っていない
- markdown 表示には marked + DOMPurify を経由

## 設計意図
- 公開掲示板モデル: 全投稿・全コメントは全ログインユーザに公開
- コメントは誰でも書ける (仕様)。削除は所有者または admin のみ
- 「他人の投稿に対する操作」は閲覧 / コメント追加までが仕様

## 命名規約
- `db.prepare(...).get()` / `db.prepare(...).run()` は better-sqlite3 の placeholder
  バインド経路 → SQLi 安全
```

それでは、リポジトリの内容を踏まえて SECURITY-CONTEXT.md を出力してください。
````

### Step 2: AI に渡す

| ツール | 使い方 |
|---|---|
| **Claude Code** (推奨) | ターゲットリポジトリで `claude` を起動 → 上記 prompt を貼り付け。リポジトリ全体を自動で読みに行きます |
| **Cursor / Copilot Chat** | リポジトリを開いた状態で chat に prompt を貼り付け |
| **Claude.ai / ChatGPT** | リポジトリ主要ファイル (auth / middleware / routes / models) を個別添付 + prompt |
| **Gemini Code Assist** | プロジェクト指定状態で prompt を投入 |

### Step 3: 人間がレビュー・調整

AI の出力は **下書き** として扱ってください:

- 「(推測)」が付いた項目は実コードと突合して確定 / 削除
- 「設計意図」セクションは AI には判断不能なので、プロダクト仕様の知識で書き換え
- 機密情報 (内部 URL / DB 名 / API キー / 顧客名) が混入していないか確認
- 各項目を 2-5 行に整理し、冗長な部分は削る

---

## 配置と参照

```
your-repo/
└── .github/
    └── security-scan-overrides/
        ├── SECURITY-CONTEXT.md          ← ここに置く
        ├── perspectives/                ← (任意)
        └── triage_prompts.yml           ← (任意)
```

caller workflow で参照:

```yaml
# .github/workflows/security-scan.yml
jobs:
  scan:
    uses: Zuck3-r/llm-security-scan/.github/workflows/scan.yml@v0.6.1
    with:
      overrides_path: .github/security-scan-overrides
      context_path:   .github/security-scan-overrides/SECURITY-CONTEXT.md
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

`context_path` を省略した場合は `${overrides_path}/SECURITY-CONTEXT.md` が fallback として読まれます。両方無ければ no-op (スキャンは動くが文脈注入は無し)。

---

## 注意点

- **長すぎない**: 全観点 × 全 LLM 呼び出しで毎回送られるため、長大な context は token コストを膨らませます。**500-1500 字程度** を目安に。
- **prompt cache が効く**: 文脈は全 LLM 呼び出しで共通の prefix なので prompt cache が効き、コスト増は限定的です。
- **更新タイミング**: 認証 framework の差し替え / 新規共通 middleware の導入 / 設計方針の変更時にレビューしてください。半年に 1 回程度が目安。
- **機密を書かない**: 顧客固有の情報、内部 URL、credentials は書かないこと。CI ログや LLM provider に送られます。

---

## 関連ドキュメント

- [README.md](../README.md) — 全体概要・観点表
- [docs/CONSUMER_SETUP.md](./CONSUMER_SETUP.md) — Level 1〜3 の段階的導入手順
- [CLAUDE.md](../CLAUDE.md) — 設計詳細
