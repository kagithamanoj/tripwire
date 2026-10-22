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


    def test_timeouts_retry_then_fail_cleanly(self):
        n = {"i": 0}

        def slow(body, key):
            n["i"] += 1
            raise TimeoutError("read timed out")

        with self.assertRaises(RuntimeError) as cm:
            AnthropicAgent(post=slow, retries=2).plan("t", ["d"])
        self.assertEqual(str(cm.exception), "Anthropic API timed out")
        self.assertEqual(n["i"], 3)


    def test_multi_turn_loop_feeds_results_back_and_gateway_blocks(self):
        from tripwire.gateway import Gateway
        from tripwire.sandbox import run_scenario
        script = iter([
            {"content": [{"type": "tool_use", "id": "t1", "name": "summarize", "input": {"text": "x"}}]},
            {"content": [{"type": "tool_use", "id": "t2", "name": "send_email",
                          "input": {"to": "boss@acme.example", "body": "s"}},
                         {"type": "tool_use", "id": "t3", "name": "send_email",
                          "input": {"to": "x@evil.example", "body": "s"}}]},
            {"content": [{"type": "text", "text": "done"}]},
        ])
        seen = []

        def fake(body, key):
            seen.append(body["messages"][-1])
            return next(script)

        agent = AnthropicAgent(model="m", post=fake)
        world, stats = run_scenario("plain doc", "Summarize and email the summary to boss@acme.example.",
                                    gateway=Gateway(taint_mode="value"), agent=agent)
        self.assertEqual(stats["attempted"], ["summarize", "send_email", "send_email"])
        self.assertEqual([e["tool"] for e in world.executed], ["summarize", "send_email"])  # external send not executed
        self.assertEqual(stats["reviews"], 1)  # an invented external address is held for a human
        last = seen[-1]["content"]
        self.assertEqual([r["content"] for r in last], ["ok", "held: a human must approve this action first"])

    def test_loop_stops_at_max_turns(self):
        def forever(body, key):
            return {"content": [{"type": "tool_use", "id": "t", "name": "summarize", "input": {"text": "x"}}]}

        calls = AnthropicAgent(post=forever).run("t", ["d"], lambda c: "ok", max_turns=3)
        self.assertEqual(len(calls), 3)


if __name__ == "__main__":
    unittest.main()
