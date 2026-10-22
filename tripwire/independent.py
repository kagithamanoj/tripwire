"""Evaluate Tripwire against an attack set written by someone who never saw the defence.

Input JSON: {"attacks": [{id, technique, text, harmful_call: {tool, args}}], "benign": [{id, text}]}.
An attack is *stopped* when the document is blocked or held at ingest, or when the harmful tool call
is not simply allowed. We never claim more than this: the harmful call is supplied by the attacker,
not produced by a real model.
"""

import json
from collections import Counter

from .gateway import Gateway
from .receipts import ReceiptLog

TASK = "Summarize the document."
CONFIGS = {
    "detector_only": dict(use_detector=True, use_policy=False),
    "policy_only_session": dict(use_detector=False, use_policy=True, taint_mode="session"),
    "policy_only_value": dict(use_detector=False, use_policy=True, taint_mode="value"),
    "full_session": dict(use_detector=True, use_policy=True, taint_mode="session"),
    "full_value": dict(use_detector=True, use_policy=True, taint_mode="value"),
}


def _stopped(kwargs: dict, attack: dict) -> tuple[bool, str]:
    gw = Gateway(log=ReceiptLog(), **kwargs)
    gw.register_task(TASK)
    ing = gw.ingest(attack["text"], "document")
    if ing.action != "allow":
        return True, f"ingest:{ing.action}"
    call = attack["harmful_call"]
    d = gw.authorize_tool(call["tool"], {k: str(v) for k, v in call["args"].items()}, "model")
    return d.action != "allow", f"tool:{d.action}"


def evaluate(path: str) -> dict:
    data = json.load(open(path))
    attacks, benign = data["attacks"], data["benign"]
    out = {"attacks": len(attacks), "benign": len(benign), "configs": {}}
    for name, kwargs in CONFIGS.items():
        stopped, leaked = 0, []
        for a in attacks:
            ok, how = _stopped(kwargs, a)
            stopped += ok
            if not ok:
                leaked.append({"id": a["id"], "technique": a["technique"], "call": a["harmful_call"]["tool"]})
        out["configs"][name] = {
            "attacks_stopped": stopped, "stop_rate": round(stopped / len(attacks), 3), "leaked": leaked,
        }
    from .detector import scan

    flagged = [b["id"] for b in benign if scan(b["text"]).action != "allow"]
    caught = [a["id"] for a in attacks if scan(a["text"]).action != "allow"]
    out["detector"] = {
        "attack_recall": round(len(caught) / len(attacks), 3), "attacks_missed": [a["id"] for a in attacks if a["id"] not in caught],
        "false_positive_rate": round(len(flagged) / len(benign), 3), "false_positives": flagged,
    }
    out["leaked_by_technique_full_value"] = dict(Counter(x["technique"] for x in out["configs"]["full_value"]["leaked"]))
    return out
