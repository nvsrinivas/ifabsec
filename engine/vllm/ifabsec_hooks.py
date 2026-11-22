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

import logging
import os
from typing import Any, Optional

_ENABLED = os.environ.get("IFAB_MODE", "off") != "off"


def block_salt_keys(request: Any, start_token_idx: int, end_token_idx: int) -> Optional[list]:
    """Extra keys for one block's hash, or None to keep vLLM's own cache_salt key."""
    if not _ENABLED:
        return None
    from ifabsec_engine.vllm_glue import block_keys

    return block_keys(request, start_token_idx, end_token_idx)


def frontend_hashes_allowed() -> bool:
    """Whether EngineCore may use block hashes a frontend computed (they never
    carry scopes, so not while ifabsec is on)."""
    if not _ENABLED:
        return True
    from ifabsec_engine.vllm_glue import ignore_frontend_hashes

    return not ignore_frontend_hashes()


def label_chat(serving: Any, request: Any, raw_request: Any, engine_inputs: list) -> Optional[str]:
    """Verify the label token and set each engine input's cache_salt.
    Returns an error message for an HTTP 400, or None on success. In observe
    mode a failure is logged and the request proceeds unlabeled."""
    if not _ENABLED:
        return None
    from ifabsec_engine import vllm_glue as glue

    err = _label(glue, serving, request, raw_request, engine_inputs)
    if err is not None and glue.config().observe:
        logging.getLogger("ifabsec").warning("%s (observe mode: not rejected)", err)
        return None
    return err


def _label(glue: Any, serving: Any, request: Any, raw_request: Any, engine_inputs: list) -> Optional[str]:
    if getattr(request, "cache_salt", None) is not None:
        return "ifabsec: cache_salt is set by the gateway, not the client"
    for engine_input in engine_inputs:
        if engine_input.get("type") != "token":
            return "ifabsec v0.1 supports text-only requests"
        if engine_input.get("cache_salt") is not None:
            return "ifabsec: cache_salt is set by the gateway, not the client"
    prompts = [list(e["prompt_token_ids"]) for e in engine_inputs]
    if not prompts or any(ids != prompts[0] for ids in prompts):
        return "ifabsec v0.1 labels one prompt per chat request"

    # Find boundaries by rendering prefixes from role and text only, with the
    # server's own template and the operator's default options: never the
    # client's documents, template options or template. If the client's extras
    # change what a template renders, the renders disagree with the prompt and
    # the boundary moves earlier (less sharing, never more).
    tokenizer = serving.renderer.tokenizer
    template_kwargs = dict(getattr(serving, "default_chat_template_kwargs", None) or {})
    for key in ("add_generation_prompt", "continue_final_message", "tools", "tokenize", "return_dict",
                "documents", "chat_template"):
        template_kwargs.pop(key, None)
    if getattr(serving, "chat_template", None):
        template_kwargs["chat_template"] = serving.chat_template
    messages = glue.render_messages(request.messages)

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
        salt = glue.label_request(  # verifies the token once for the request
            glue.config(), glue.verifier(), header, messages, prompts[0],
            render_prefix, tokenize, tools=tools, render_tools=render_tools,
        )
    except glue.TokenError as e:
        return f"ifabsec: {e}"
    for engine_input in engine_inputs:
        engine_input["cache_salt"] = salt
    return None
