# Precedent demo guide

Start the services using the README. The scenario already starts with a copied payments credential. All company names and historical cases are fictional.

## Three primary controls

1. **Replay H41 proposal** submits a historical immediate-revocation proposal to the gate. It should show REVISE while consumers depend on the old credential. Open **Show me why** to see policies, historical cases, paths, and receipt status.
2. **Compare response** shows separate counterfactual model results beside the latest live-run probes. Payment failure after immediate revocation is the comparison’s key observation. The two snapshots and observation times are not yet guaranteed to match.
3. **Launch attack response** starts Qoder’s investigation. Follow what the agent actually proposes. Session completion alone does not establish recovery.

## Evidence and scenario tools

Select a decision in the action stream to keep it in view. Switch between Infrastructure, Memory, and Sources. The graph’s text alternative lists the same displayed nodes and links.

Open **Scenario tools & reset** to inject a forged runbook. Inspect the resulting denial and source authority. Reset restores live topology while preserving graph memory; it does not clear the full seeded database.

Use **Show me why → Export selected decision** to save the selected decision and retained events. The export is a partial inspection artifact, not a complete durable recording.

## Honest presentation

Say “historical proposal replay” for H41 and “counterfactual model” for the failed-response comparison. Do not attribute a supplied proposal to Qoder. Treat current probe results as point-in-time modeled observations, not proof of uninterrupted real payments.

The complete three-minute recovery-and-learning story remains an acceptance target. See the [build audit](build-audit.md) before claiming that the live agent completed recovery or that a new verified case changed the next session.
