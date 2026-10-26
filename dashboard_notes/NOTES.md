# Dashboard notes

The V4 dashboard reuses Sentinel V3's real-time dashboard. V4 needs one new
view: **red vs blue, live** — red-team bot probes on one side, Sentinel's
triage → reasoning → approval → containment responses on the other.

TODO (Phase 1, day 8):
- [ ] Event feed shows which Laya decisions auto-acted vs escalated.
- [ ] Escalated cases show Muse Spark's explanation inline.
- [ ] Pending Telegram approvals are visible with approve/deny state.
- [ ] Containment actions are labelled DRY-RUN unless the env gate is on.
- [ ] One clean full run recorded as the demo backup video (day 8-9).
