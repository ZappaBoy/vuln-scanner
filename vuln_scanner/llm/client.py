"""Thin OpenAI-compatible LLM client — endpoint-agnostic."""

import json
import logging
from typing import Any

log = logging.getLogger(__name__)


class LLMClient:
    """Wraps the openai SDK; works with any OpenAI-compatible endpoint."""

    def __init__(self, config: "LLMConfig") -> None:  # noqa: F821
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "openai package is required for LLM analysis. Add 'openai' to your dependencies."
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": config.api_key or "sk-placeholder",
            "timeout": config.timeout,
            "max_retries": config.max_retries,
        }
        if config.base_url:
            kwargs["base_url"] = config.base_url
        if config.organization:
            kwargs["organization"] = config.organization
        if config.extra_headers:
            kwargs["default_headers"] = config.extra_headers
        if config.extra_query:
            kwargs["default_query"] = config.extra_query

        self._client = OpenAI(**kwargs)
        self._config = config

    def _sampling_kwargs(self) -> dict[str, Any]:
        cfg = self._config
        kw: dict[str, Any] = {}
        if cfg.temperature is not None:
            kw["temperature"] = cfg.temperature
        if cfg.top_p is not None:
            kw["top_p"] = cfg.top_p
        if cfg.max_tokens is not None:
            kw["max_tokens"] = cfg.max_tokens
        if cfg.frequency_penalty is not None:
            kw["frequency_penalty"] = cfg.frequency_penalty
        if cfg.presence_penalty is not None:
            kw["presence_penalty"] = cfg.presence_penalty
        if cfg.seed is not None:
            kw["seed"] = cfg.seed
        if cfg.stop is not None:
            kw["stop"] = cfg.stop
        if cfg.extra_body:
            kw["extra_body"] = cfg.extra_body
        return kw

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        """Send a chat completion and return the parsed JSON response.

        Raises ValueError if the response cannot be parsed as JSON.
        """
        kw = self._sampling_kwargs()
        try:
            response = self._client.chat.completions.create(
                model=self._config.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                **kw,
            )
            content = response.choices[0].message.content or "{}"
            return json.loads(content)
        except json.JSONDecodeError as exc:
            log.warning("LLM returned non-JSON response: %s", exc)
            raise ValueError(f"LLM response was not valid JSON: {exc}") from exc
        except Exception as exc:
            log.error("LLM API error: %s", exc)
            raise
