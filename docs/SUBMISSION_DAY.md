# Submission day runbook - Thu Oct 22, 2026 (all times CT)

Official schedule (organizer email, Oct 17): opening 7:00 AM, repos open 7:00 AM,
mentor check-ins 12:00-1:00 PM, **hard stop for code 5:00 PM**, judging and pitches
5:30-6:30 PM, winners 7:00 PM.

## Before 7:00 AM
- [ ] Merge the `submission-fixes-oct22` branch into main (fixes: deck, live URL in README, stale doc lines).
- [ ] Meghana: accept the tripwire GitHub invite (github.com/kagithamanoj/tripwire/invitations).
- [ ] Both: complete and sign `docs/AI_USAGE.md`, including the "What the humans did" section. Commit it.
- [ ] Interviews: line up 3-5 short chats with agent builders for Problem & Impact quotes (slide 3, PITCH.md slides 2-3). Ask in Slack early.

## 7:00 AM - repos open
- [ ] Push tripwire main into the team repo CommunityHackathons/adai26-team-022 (the shared repo the judges get).
- [ ] Make github.com/kagithamanoj/tripwire public (submission checklist #6: public or shared link).
- [ ] Verify from a private window: repo loads, README live-demo link works, `curl <demo url>/healthz` returns ok.

## During the day
- [ ] 12:00-1:00 PM mentor check-in: bring the demo and one question (track confirmation: team-022 submits as SECURE).
- [ ] 2:00-3:00 PM: Manoj records Day Two DevOps. Meghana covers the room; no code changes that need him.
- [x] Real-model eval DONE via the Anthropic API (Bedrock quota was declined); see docs/REAL_MODEL_EVAL.md. (Old note:) Bedrock: if the quota cases move, Manoj files the Anthropic use-case form, then run `scripts/live_eval.py` and put real numbers in README / SYSTEM_CARD / deck slide 7. If not, the honest "implemented, blocked on quota" line stays.
- [ ] Rehearse the 3-minute demo twice out loud (script in docs/PROJECT_GUIDE.md).

## By 4:00 PM (one hour before hard stop)
- [ ] Regenerate logs: run tests, eval, arena; commit `logs/`.
- [ ] Re-run `python3 scripts/check_secrets.py` (expect 0 findings).
- [ ] Final check of docs/SUBMISSION_CHECKLIST.md: every row DONE or honestly PARTIAL.
- [ ] Push everything to BOTH repos. Confirm the team repo shows the final tree.

## 5:00 PM - hard stop. No more pushes.
## 5:30-6:30 PM - judging and pitches. Deck: docs/deck/tripwire-pitch.pptx.
## After judging
- [ ] `./scripts/destroy_aws.sh` to stop AWS cost (keep the demo up until winners are announced at 7:00 PM).
