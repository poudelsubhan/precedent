# Build acceptance — September 12, 2026

The core recovery-and-learning loop is verified. The project is ready for a narrated demo. This report distinguishes recorded evidence from implementation and outstanding submission work.

## Recorded acceptance

| Phase                            | Implementation and evidence                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 — Contracts and Qoder boundary | Pinned SDK 1.0.39, typed MCP tools, actual custom reads and host permission callbacks. The recorded recovery contains one REVISE with no receipt and ten ALLOW actions with receipts.                                                                                                                                                     |
| 1 — Working range                | Separate checkout, workers A/B, gateway, ledger, legitimate load, device-session attacker and copied-credential attacker. Native processes and Docker isolation. HMAC workload identity with expiring nonces, real HTTP probes, durable controller state/idempotency and ledger. Docker range proof passes.                               |
| 2 — Graph                        | Dependency paths include the credential-use edge. Pattern/class matching, verified-outcome/source/precondition eligibility and ranking determine recovery suggestions. Missing/conflicting facts hold action. New decisions retain immutable facts, snapshot, policies and query references.                                              |
| 3 — Gate                         | Exact scoped approvals, expiry, serialized execution, revalidation, durable intents and receipts. Integration proof rejects missing identity, changed arguments and stale versions; duplicate execution returns one receipt. Unknown outcomes require durable range readback before reconciliation.                                       |
| 4 — Runtime                      | Actual Qoder recovery completed. Initial device-isolation proposal was revised; the agent quarantined, invalidated sessions, isolated the device, created a replacement, migrated/verified both workers, switched traffic, and revoked the old credential. Cancellation and persisted-session resume are implemented.                     |
| 5 — Console                      | Precedent graphite/cobalt/violet design, three primary controls, current/history/source views, immutable trace display, real request counters/window, meaningful receipts, optional SDK telemetry, full run export, variants and reset controls. Responsive and keyboard checks performed.                                                |
| 6 — Poisoning and learning       | Forged, forged-copy and genuinely verified stale evidence are rejected. Independent payment/attacker/ledger probes promoted a trusted recovery case. A fresh Qoder session cited that exact new case and completed another recovery. Missing gateway/failed standby/additional-consumer/staging changes are covered by the broker matrix. |
| 7 — Demo package                 | Recorded original events, complete decision reports, README, architecture, setup, sponsor explanation, keywords, 20 GitHub topics, 200-word description, timed personal narration script, and silent 2:40 event-replay video.                                                                                                             |

## Live evidence

- [First recovery](evidence/live-recovery.json): `8387cd31-f968-430f-9ae0-2615ab387412`. Qoder's first intervention appeared about 17 seconds after run start. One REVISE followed by ten ALLOW decisions. Payment and ledger passed; attacker returned 403. Learned case: `recovery-8387cd31-f968-430f-9ae0-2615ab387412`.
- [Fresh session](evidence/fresh-session.json): `85affbb4-2035-4d95-805d-578d6f6a7fa2`. A distinct session cited the first learned case in its proposals and final report, completed recovery and created another verified case.
- [Forged rejection](evidence/forged-rejection.json): supplied demo injection, not an autonomous agent proposal. DENY with an untrusted source and no trusted verification.
- [Docker range proof](evidence/range-proof.json): independent HTTP requests demonstrate copied-key access after device isolation, same-snapshot counterfactual outage, quarantine continuity, migration, final revocation and ledger checks.
- [Broker integration proof](evidence/broker-proof.json): seven acceptance groups cover authentication, zero-receipt revision, poisoning/staleness, changed history, four environment variants, exact arguments/idempotency and stale approvals.

Reports contain the observations available at export; request counters explicitly carry their observation window. They do not assert zero failures outside that window. Fictional seeded histories are examples, not production incident data. The video is an event replay with compressed timing, not a screen capture or a newly running agent.

## Validation and limits

21 automated tests pass; workspace type checking and the production build pass. Graph-outage behavior has evaluator fault coverage. Full transport fault-injection, signed-envelope replay integration, restart/resume rehearsal and a complete independent security audit have not been certified. Source-chain display covers returned source/verification paths; it is not a general document-chain trust engine. The live demonstration uses the native HTTP processes; Docker isolation is separately exercised by the range proof.

The initial run exposed incomplete action argument documentation; the gate rejected those malformed attempts. After correcting the description, the two recorded runs above succeeded. Failed attempts are not presented as successful evidence.

Qoder development review was explicitly waived by the owner. Runtime Qoder evidence is included; no development review is claimed.

## Finish the submission

Record the [timed script](demo-script.md) in the project owner's own voice, keep the final video under three minutes, and upload it with the repository link. Organizer-specific deadline, judging rules, roster, team limits and submission destination were not supplied and are not invented here. No public hosted demo URL is claimed.
