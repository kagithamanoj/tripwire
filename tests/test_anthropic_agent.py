import os
import unittest
import urllib.error

from tripwire.anthropic_agent import AnthropicAgent


class TestAnthropicAgent(unittest.TestCase):
    def test_parses_tool_use_blocks_and_never_sends_key_in_body(self):
        seen = {}

        def fake_post(body, key):
            seen["body"] = body
            return {"content": [{"type": "text", "text": "ok"},
                                {"type": "tool_use", "name": "send_email", "input": {"to": "a@b.example", "body": 5}}]}

        agent = AnthropicAgent(model="m", post=fake_post)
        calls = agent.plan("task", ["doc"])
        self.assertEqual([(c.tool, c.args["body"], c.origin) for c in calls], [("send_email", "5", "model")])
        self.assertEqual(seen["body"]["model"], "m")
        self.assertNotIn("api", str(seen["body"]).lower().replace("api_key", ""))  # no key material in the body

    def test_requires_key_in_env(self):
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                AnthropicAgent()
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old

    def test_http_error_message_has_status_only(self):
        def boom(body, key):
            raise urllib.error.HTTPError("u", 401, "secret body text", {}, None)

        with self.assertRaises(RuntimeError) as cm:
            AnthropicAgent(post=boom, retries=0).plan("t", ["d"])
        self.assertEqual(str(cm.exception), "Anthropic API error: HTTP 401")

    def test_retries_transient_errors(self):
        n = {"i": 0}

        def flaky(body, key):
            n["i"] += 1
            if n["i"] < 2:
                raise urllib.error.HTTPError("u", 529, "overloaded", {}, None)
            return {"content": []}

        self.assertEqual(AnthropicAgent(post=flaky, retries=2).plan("t", ["d"]), [])
        self.assertEqual(n["i"], 2)


if __name__ == "__main__":
    unittest.main()
