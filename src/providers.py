"""LLM プロバイダー抽象。

優先順位:
1. **OpenAIProvider** — `OPENAI_API_KEY` が設定されていれば採用。
   Chat Completions API + JSON mode で叩く。
2. **VertexAIProvider** — `GOOGLE_CLOUD_PROJECT` が設定されていれば採用。
   `google-github-actions/auth@v2` 等で ADC が用意されていることを前提とする。
   GCP プロジェクト quota を使うため、AI Studio の Free Tier `limit: 0` の罠に
   ハマらない。
3. **GeminiProvider** — フォールバック。Generative Language API キーで叩く。

Claude を追加する際は `LLMProvider` を継承して `get_provider()` の優先順位に挿し込む。
"""
from __future__ import annotations

import asyncio
import os
import sys
from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Optional, TypeVar


T = TypeVar("T")


class LLMProvider(ABC):
    name: str = "abstract"
    model: str = ""

    @abstractmethod
    async def call(self, system_prompt: str, user_prompt: str) -> dict:
        """Returns: {"text": str, "tokens_in": int, "tokens_out": int}"""
        ...


class _RetryMixin:
    """429 / ResourceExhausted を検出して指数バックオフで 3 回までリトライ。"""

    RETRY_DELAYS = (5, 15, 45)

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        name = type(exc).__name__
        msg = str(exc)
        if name == "ResourceExhausted":
            return True
        if "429" in msg:
            return True
        ml = msg.lower()
        return "quota" in ml or "rate limit" in ml or "exhausted" in ml

    async def _with_retry(self, label: str, fn: Callable[[], Awaitable[T]]) -> T:
        last_exc: Optional[Exception] = None
        for attempt in range(len(self.RETRY_DELAYS) + 1):
            try:
                return await fn()
            except Exception as e:  # noqa: BLE001
                last_exc = e
                if not self._is_quota_error(e) or attempt >= len(self.RETRY_DELAYS):
                    raise
                delay = self.RETRY_DELAYS[attempt]
                print(
                    f"[{label}] 429/quota; retrying in {delay}s "
                    f"(attempt {attempt + 1}/{len(self.RETRY_DELAYS)}): {e}",
                    file=sys.stderr,
                )
                await asyncio.sleep(delay)
        assert last_exc is not None
        raise last_exc


# ────────── OpenAI（最優先）──────────
class OpenAIProvider(LLMProvider, _RetryMixin):
    """Chat Completions API + JSON mode で叩く。"""

    name = "openai"
    DEFAULT_MODEL = "gpt-5.5"

    def __init__(self, api_key: str, model: Optional[str] = None) -> None:
        from openai import AsyncOpenAI

        self._client = AsyncOpenAI(api_key=api_key)
        self.model = (
            model
            or os.environ.get("LLM_MODEL")
            or os.environ.get("OPENAI_MODEL")
            or self.DEFAULT_MODEL
        ).strip()

    # GPT-5 / o-series reasoning models reject any non-default `temperature`
    # (returns 400 "Unsupported value: 'temperature'"). Only pass it for
    # models known to accept it.
    @staticmethod
    def _supports_temperature(model: str) -> bool:
        m = model.lower()
        if m.startswith(("gpt-5", "o1", "o3", "o4")):
            return False
        return True

    async def call(self, system_prompt: str, user_prompt: str) -> dict:
        async def _do() -> dict:
            kwargs: dict = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                "response_format": {"type": "json_object"},
            }
            if self._supports_temperature(self.model):
                kwargs["temperature"] = 0.1
            resp = await self._client.chat.completions.create(**kwargs)
            choice = resp.choices[0] if resp.choices else None
            text = (getattr(getattr(choice, "message", None), "content", None) or "").strip()
            usage = resp.usage
            tokens_in  = int(getattr(usage, "prompt_tokens",     0) or 0) if usage else 0
            tokens_out = int(getattr(usage, "completion_tokens", 0) or 0) if usage else 0
            return {"text": text, "tokens_in": tokens_in, "tokens_out": tokens_out}

        return await self._with_retry("openai", _do)


# ────────── Vertex AI ──────────
class VertexAIProvider(LLMProvider, _RetryMixin):
    """Vertex AI 経由で Gemini を叩く。

    認証は ADC（Application Default Credentials）。GitHub Actions では
    `google-github-actions/auth@v2` が `GOOGLE_APPLICATION_CREDENTIALS` を
    設定するため、追加コードは不要。
    """

    name = "vertex"
    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self, project: str, location: str, model: Optional[str] = None) -> None:
        import vertexai
        from vertexai.generative_models import (
            GenerativeModel,
            HarmBlockThreshold,
            HarmCategory,
        )

        self.model = (model or os.environ.get("LLM_MODEL") or self.DEFAULT_MODEL).strip()
        vertexai.init(project=project, location=location)

        self._GenerativeModel = GenerativeModel
        # Vertex AI の SDK は enum で safety_settings を受ける
        self._safety = {
            HarmCategory.HARM_CATEGORY_HARASSMENT:        HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH:       HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }
        self._project  = project
        self._location = location

    async def call(self, system_prompt: str, user_prompt: str) -> dict:
        async def _do() -> dict:
            gm = self._GenerativeModel(self.model, system_instruction=system_prompt)
            resp = await gm.generate_content_async(
                user_prompt,
                generation_config={
                    "temperature":         0.1,
                    "response_mime_type":  "application/json",
                },
                safety_settings=self._safety,
            )
            text = (getattr(resp, "text", "") or "").strip()
            usage = getattr(resp, "usage_metadata", None)
            tokens_in  = int(getattr(usage, "prompt_token_count",     0) or 0) if usage else 0
            tokens_out = int(getattr(usage, "candidates_token_count", 0) or 0) if usage else 0
            return {"text": text, "tokens_in": tokens_in, "tokens_out": tokens_out}

        return await self._with_retry("vertex", _do)


# ────────── Generative Language API（フォールバック）──────────
class GeminiProvider(LLMProvider, _RetryMixin):
    """Generative Language API（AI Studio キー方式）。

    Free Tier プロジェクトでは `limit: 0` の罠があるため非推奨だが、
    Vertex AI が使えない環境のフォールバックとして残す。
    """

    name = "gemini"
    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self, api_key: str, model: Optional[str] = None) -> None:
        import google.generativeai as genai

        self._genai = genai
        self.model = (
            model
            or os.environ.get("LLM_MODEL")
            or os.environ.get("GEMINI_MODEL")
            or self.DEFAULT_MODEL
        ).strip()
        genai.configure(api_key=api_key)
        self._safety = {
            "HARM_CATEGORY_HARASSMENT":        "BLOCK_NONE",
            "HARM_CATEGORY_HATE_SPEECH":       "BLOCK_NONE",
            "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
            "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
        }

    async def call(self, system_prompt: str, user_prompt: str) -> dict:
        async def _do() -> dict:
            gm = self._genai.GenerativeModel(self.model, system_instruction=system_prompt)
            resp = await gm.generate_content_async(
                user_prompt,
                generation_config={
                    "temperature":         0.1,
                    "response_mime_type":  "application/json",
                },
                safety_settings=self._safety,
            )
            text = (getattr(resp, "text", "") or "").strip()
            usage = getattr(resp, "usage_metadata", None)
            tokens_in  = int(getattr(usage, "prompt_token_count",     0) or 0) if usage else 0
            tokens_out = int(getattr(usage, "candidates_token_count", 0) or 0) if usage else 0
            return {"text": text, "tokens_in": tokens_in, "tokens_out": tokens_out}

        return await self._with_retry("gemini", _do)


# ────────── ファクトリ ──────────
def _try_openai() -> Optional[LLMProvider]:
    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    return OpenAIProvider(api_key=api_key) if api_key else None


def _try_vertex() -> Optional[LLMProvider]:
    project = (os.environ.get("GOOGLE_CLOUD_PROJECT") or "").strip()
    if not project:
        return None
    location = (os.environ.get("GOOGLE_CLOUD_LOCATION") or "us-central1").strip()
    return VertexAIProvider(project=project, location=location)


def _try_gemini() -> Optional[LLMProvider]:
    api_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
    return GeminiProvider(api_key=api_key) if api_key else None


def get_provider() -> LLMProvider:
    """環境変数から最適なプロバイダーを返す。

    `LLM_PROVIDER` env で明示指定されていればそれを優先（CI 側で `Detect provider`
    ステップの結果を渡す用途）。未指定なら openai → vertex → gemini の順で
    auto detect する。
    """
    forced = (os.environ.get("LLM_PROVIDER") or "").strip().lower()
    if forced == "openai":
        p = _try_openai()
        if not p:
            raise RuntimeError("LLM_PROVIDER=openai but OPENAI_API_KEY is empty.")
        return p
    if forced == "vertex":
        p = _try_vertex()
        if not p:
            raise RuntimeError("LLM_PROVIDER=vertex but GOOGLE_CLOUD_PROJECT is empty.")
        return p
    if forced == "gemini":
        p = _try_gemini()
        if not p:
            raise RuntimeError("LLM_PROVIDER=gemini but GEMINI_API_KEY is empty.")
        return p

    # auto detect (forced は空 or 未知の値)
    provider = _try_openai() or _try_vertex() or _try_gemini()
    if provider is None:
        raise RuntimeError(
            "No LLM credentials found. Set one of: "
            "OPENAI_API_KEY (preferred), GOOGLE_CLOUD_PROJECT (Vertex AI), "
            "or GEMINI_API_KEY (Generative Language API; fallback)."
        )
    return provider
