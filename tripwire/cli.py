"""Command line: python -m tripwire {demo,eval,arena,serve}"""

import argparse
import json
import sys

from . import arena, corpus
from .gateway import Gateway
from .receipts import HmacSigner, ReceiptLog, verify
from .sandbox import harmful, run_scenario


def demo() -> None:
    for attack in (corpus.ATTACKS[0], corpus.ATTACKS[5]):
        print("=" * 72)
        _demo_one(attack)


def _demo_one(attack: dict) -> None:
    print(f"ATTACK {attack['id']} ({attack['kind']})")
    print("TASK: 'Summarize the document.'  DOC:", attack["text"][:90], "...\n")
    world, _ = run_scenario(attack["text"])
    print("UNPROTECTED agent executed:")
    for e in world.executed:
        print("  ", e["tool"], e["args"])
    print("  -> attacker goal reached:", harmful(world, attack["harmful"]), "\n")

    signer = HmacSigner()
    gw = Gateway(log=ReceiptLog(signer=signer))
    world, stats = run_scenario(attack["text"], gateway=gw)
    print("WITH TRIPWIRE agent executed:")
    for e in world.executed:
        print("  ", e["tool"], e["args"])
    print("  -> attacker goal reached:", harmful(world, attack["harmful"]))
    print("  -> pending human reviews:", len(gw.queue.pending()), "\n")
    print("SIGNED RECEIPTS:")
    for r in gw.log.receipts:
        ev = r["event"]
        print(f"  #{r['seq']} {ev['type']:<7} {ev.get('action', ''):<7} {ev.get('tool', ev.get('source', ''))}  sig={r['sig'][:12]}")
    print("  chain verifies:", verify(gw.log.receipts, signer)[0])
    first = gw.log.receipts[0]["event"]
    first["action"] = "allow" if first["action"] != "allow" else "block"  # tamper
    print("  after tampering with receipt #0:", verify(gw.log.receipts, signer))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tripwire")
    p.add_argument("command", choices=["demo", "eval", "arena", "utility", "serve"])
    p.add_argument("--port", type=int, default=8080)
    a = p.parse_args(argv)
    if a.command == "demo":
        demo()
    elif a.command == "eval":
        print(json.dumps(arena.run_seed_eval(), indent=2))
    elif a.command == "arena":
        print(json.dumps(arena.run_arena(), indent=2))
    elif a.command == "utility":
        from .utility import run_utility
        print(json.dumps(run_utility(), indent=2))
    else:
        from .server import serve
        serve(a.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
