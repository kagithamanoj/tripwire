# Submission Checklist (maps handbook items to artifacts)

Status: DONE = in repo; TODO = needs the team.

| # | Handbook item | Artifact | Status |
|---|---|---|---|
| 1 | Project name + track | Tripwire, SECURE (README) | DONE |
| 2 | Elevator pitch | README top; `PITCH.md` slide 1 | DONE |
| 3 | Problem definition + personas | `PITCH.md` slides 2-3; **needs real interviews** | PARTIAL |
| 4 | Architecture diagram | `ARCHITECTURE.md` (Mermaid) | DONE |
| 5 | Live demo link or local script | `python -m tripwire demo` / `serve`; live AWS URL in `DEPLOY_AWS.md` | DONE |
| 6 | Public GitHub repo | github.com/kagithamanoj/tripwire | TODO at submission: repo is private now; make public AND push to the team repo (CommunityHackathons/adai26-team-022, opens 8 AM ET) |
| 7 | Technical inventory | `INVENTORY` section in README (stdlib only) | DONE |
| 8 | AI usage declaration | `AI_USAGE.md` | TODO: complete + sign |
| 9 | Risk registry / threat model | `THREAT_MODEL.md` | DONE |
| 10 | Test execution logs | `logs/test_run.log`, `logs/eval.json`, `logs/arena.json` | DONE (60 tests, Oct 22; regenerate once more after the final merge) |
| 11 | Governance charter / System Card | `SYSTEM_CARD.md` | DONE |
| 12 | Pitch deck | `docs/deck/tripwire-pitch.pptx` (source: `docs/deck/slides.md`) | Deck DONE; rehearsal TODO |

| Guideline | Evidence |
|---|---|
| P-01 team 1-5 | Register roster via organizer link (TODO) |
| P-02 one track | SECURE only |
| P-03 baseline metrics | Unprotected attack success 100% (measured); add cited external stats |
| P-04 working system | Local reproducible demo + AWS URL |
| P-05 AI declaration | `AI_USAGE.md` signed |
| P-06 risk control | threat model, system card, trust boundaries |
| P-07 no secrets | `scripts/check_secrets.py` output in `logs/secret_scan.log` |

Open questions for organizers: team registration link; whether P-04 applies to SECURE (we satisfy it anyway).
