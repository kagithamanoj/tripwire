"""Real-LLM agent adapter for the Anthropic Messages API (standard library only).

The API key is read from the ANTHROPIC_API_KEY environment variable at call time. It is never
logged, printed, written to disk, or included in an error message. Model: TRIPWIRE_MODEL_ID
(default claude-haiku-5-5, the cheapest current model).
"""

import json
import os
import time
import urllib.error
import urllib.request

from .llm_agent import SYSTEM, tool_config
from .sandbox import Call

URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-5-5"


def _tools() -> list[dict]:
    return [{"name": t["toolSpec"]["name"], "description": t["toolSpec"]["description"],
             "input_schema": t["toolSpec"]["inputSchema"]["json"]} for t in tool_config()["tools"]]


def _post(body: dict, key: str, timeout: float = 30.0) -> dict:
    req = urllib.request.Request(
        URL, data=json.dumps(body).encode(), method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


class AnthropicAgent:
    def __init__(self, model: str | None = None, post=None, retries: int = 2):
        self.model = model or os.environ.get("TRIPWIRE_MODEL_ID") or DEFAULT_MODEL
        if not os.environ.get("ANTHROPIC_API_KEY") and post is None:
            raise RuntimeError("set ANTHROPIC_API_KEY in your own shell (never paste it into chat or commit it)")
        self._post = post or _post
        self.retries = retries
        self.calls = 0

    def plan(self, task: str, docs: list[str]) -> list[Call]:
        body = {
            "model": self.model, "max_tokens": 1024, "system": SYSTEM, "tools": _tools(),
            "messages": [{"role": "user", "content": task + "\n\n" + "\n".join(
                f"<document>\n{d}\n</document>" for d in docs)}],
        }
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        for attempt in range(self.retries + 1):
            try:
                resp = self._post(body, key)
                break
            except urllib.error.HTTPError as e:  # status code only: the body may echo request details
                if e.code in (429, 500, 529) and attempt < self.retries:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"Anthropic API error: HTTP {e.code}") from None
            except TimeoutError:
                if attempt < self.retries:
                    continue
                raise RuntimeError("Anthropic API timed out") from None
            except urllib.error.URLError as e:
                raise RuntimeError(f"Anthropic API unreachable: {type(e.reason).__name__}") from None
        self.calls += 1
        return [Call(b["name"], {k: str(v) for k, v in b["input"].items()}, "model")
                for b in resp.get("content", []) if b.get("type") == "tool_use"]
