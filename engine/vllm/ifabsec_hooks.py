"""ifabsec: zero-trust scopes for the prefix cache (https://github.com/nvsrinivas/ifabsec).

Every hook is a no-op unless IFAB_MODE is observe or enforce. When active:

* the OpenAI chat endpoint requires a gateway-signed X-Ifab-Token, checks
  approved shared content, and puts a MAC'd internal salt describing which
  prompt tokens belong to which scope in the request's cache_salt;
* every prefix-cache block hash carries its block's scope, so identical text
  under different scopes never matches;
* any request without a valid internal salt (other endpoints, client-chosen,
  forged or stale salts) gets a key of its own on every block.

v0.1 supports text-only chat requests (no multimodal or embeddings sharing).
"""

from __future__ import annotations

import os
from typing import Any, Optional

_ENABLED = os.environ.get("IFAB_MODE", "off") != "off"


def block_salt_keys(request: Any, start_token_idx: int, end_token_idx: int) -> Optional[list]:
    """Extra keys for one block's hash, or None to keep vLLM's own cache_salt key."""
    if not _ENABLED:
        return None
    from ifabsec_engine.vllm_glue import block_keys

    return block_keys(request, start_token_idx, end_token_idx)


def label_chat(serving: Any, request: Any, raw_request: Any, engine_inputs: list) -> Optional[str]:
    """Verify the label token and set each engine input's cache_salt.
    Returns an error message for an HTTP 400, or None on success."""
    if not _ENABLED:
        return None
    from ifabsec_engine import vllm_glue as glue

    if getattr(request, "cache_salt", None) is not None:
        return "ifabsec: cache_salt is set by the gateway, not the client"
    for engine_input in engine_inputs:
        if engine_input.get("type") != "token" or engine_input.get("cache_salt") is not None:
            return "ifabsec v0.1 supports text-only requests"

    tokenizer = serving.renderer.tokenizer
    # Render prefixes the way vLLM rendered the prompt: same template and
    # template variables, but never a generation prompt or a continued message.
    template_kwargs = dict(serving._effective_chat_template_kwargs(request) or {})
    for key in ("add_generation_prompt", "continue_final_message", "tools", "tokenize", "return_dict"):
        template_kwargs.pop(key, None)
    template = getattr(request, "chat_template", None) or getattr(serving, "chat_template", None)
    if template:
        template_kwargs["chat_template"] = template
    messages = [
        m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else dict(m)
        for m in request.messages
    ]

    # The tools vLLM renders into the prompt (online_renderer.render_chat).
    tools = [t.model_dump() for t in (getattr(request, "tools", None) or [])] or None
    render_tools = tools
    if tools and request.tool_choice == "none" and getattr(serving, "exclude_tools_when_tool_choice_none", False):
        render_tools = None

    def render_prefix(k: int, with_tools=None) -> str:
        return tokenizer.apply_chat_template(
            messages[:k], tools=with_tools, tokenize=False, add_generation_prompt=False, **template_kwargs
        )

    def tokenize(text: str) -> list:
        return tokenizer.encode(text, add_special_tokens=False)

    header = raw_request.headers.get("x-ifab-token") if raw_request is not None else None
    try:
        for engine_input in engine_inputs:
            engine_input["cache_salt"] = glue.label_request(
                glue.config(), glue.verifier(), header, messages, list(engine_input["prompt_token_ids"]),
                render_prefix, tokenize, tools=tools, render_tools=render_tools,
            )
    except glue.TokenError as e:
        return f"ifabsec: {e}"
    return None
