"""ifabsec: zero-trust scopes for the prefix cache (https://github.com/nvsrinivas/ifabsec).

Every hook is a no-op unless IFAB_MODE is observe or enforce. When active:

* the OpenAI chat endpoint requires a gateway-signed X-Ifab-Token, checks
  approved shared content, and attaches a MAC'd internal salt describing which
  prompt tokens belong to which scope;
* radix-cache keys carry each token's scope, so identical text under different
  scopes never matches;
* any request without a valid internal salt (other endpoints, forged or
  stale salts) gets a cache namespace of its own.

v0.1 supports RadixCache and the default UnifiedRadixCache (no HiCache,
storage prefetch, SWA or multimodal sharing).
"""

from __future__ import annotations

import os

_ENABLED = os.environ.get("IFAB_MODE", "off") != "off"


def scoped_key(req, token_ids):
    """(token_ids, cache_salt) to build a RadixKey for ``req``."""
    if not _ENABLED:
        return token_ids, req.cache_salt
    from ifabsec_engine.sglang_glue import scoped_key as _scoped_key

    return _scoped_key(req, token_ids)


def label_chat(serving, request, raw_request, adapted_request):
    """Verify the label token and attach the internal salt to a chat request."""
    if not _ENABLED:
        return adapted_request
    from ifabsec_engine import sglang_glue as glue

    if request.cache_salt is not None or adapted_request.cache_salt is not None:
        raise ValueError("ifabsec: cache_salt is set by the gateway, not the client")
    for field in ("image_data", "video_data", "audio_data"):
        if getattr(adapted_request, field, None):
            raise ValueError("ifabsec v0.1 supports text-only requests")

    tokenizer = serving.tokenizer_manager.tokenizer
    if adapted_request.input_ids is not None:
        input_ids = list(adapted_request.input_ids)
    else:
        # Label exactly the ids the model will see: tokenize here and pass ids.
        input_ids = tokenizer.encode(adapted_request.text, add_special_tokens=False)
        adapted_request.input_ids = input_ids
        adapted_request.text = None

    messages = [
        m.model_dump(exclude_none=True) if hasattr(m, "model_dump") else dict(m)
        for m in request.messages
    ]

    # The tools SGLang renders into the prompt (serving_chat: model_dump of
    # request.tools, filtered to the named function for a specific tool_choice).
    tools = [t.model_dump() for t in (getattr(request, "tools", None) or [])] or None
    choice = getattr(request, "tool_choice", None)
    render_tools = tools
    if tools and choice == "none":
        render_tools = None
    elif tools and choice is not None and not isinstance(choice, str):
        render_tools = [t for t in tools if t["function"]["name"] == choice.function.name] or None

    def render_prefix(k: int, with_tools=None) -> str:
        return tokenizer.apply_chat_template(
            messages[:k], tools=with_tools, tokenize=False, add_generation_prompt=False
        )

    def tokenize(text: str) -> list:
        return tokenizer.encode(text, add_special_tokens=False)

    header = raw_request.headers.get("x-ifab-token") if raw_request is not None else None
    try:
        salt = glue.label_request(
            glue.config(), glue.verifier(), header, messages, input_ids, render_prefix, tokenize,
            tools=tools, render_tools=render_tools,
        )
    except glue.TokenError as e:
        raise ValueError(f"ifabsec: {e}") from e
    adapted_request.cache_salt = salt
    return adapted_request
