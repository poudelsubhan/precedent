# Precedent — personal narration for the 2:40 recording

Speak in your own voice. The timestamps match [the silent recorded demo](media/recorded-demo.mp4). Read only the quoted narration. The replay compresses the timing of actual recorded runs. Target 2:40; the submission limit is 3:00.

## 0:00–0:25 · The problem and the intervention

“Imagine your company’s payment system is under attack. Someone has stolen its access key. Cancelling that key seems sensible — until you realise it also stops your customers from paying.

“Precedent helps an AI responder stop the attack without creating another problem. Watch Qoder propose a response, get an explanation of why it is insufficient, and change its approach.”

## 0:25–0:55 · Qoder and the new idea

“This is a recording of Qoder actually doing the work. It investigates the incident, reads previous cases, and carries out the recovery.

“Precedent gives it something ordinary instructions don’t: checked experience connected to the current situation. Neo4j, a graph database, connects the services, their dependencies, previous outcomes, and the sources behind each claim.

“So the question becomes: did this response work before, and do the conditions still match?”

## 0:55–1:35 · Working technology and measured results

“Every proposed change passes through a separate execution service. An approval covers one exact action. Qoder cannot approve itself or change the action after approval.

“Here, it restricts the stolen key, moves the payment services to a replacement, checks them, and then cancels the old key.

“These are working local services exchanging real requests, not a diagram pretending to recover. Payments succeed. The attacker is blocked. The payment records check out. Each action has a receipt, and we can inspect the evidence behind the decision.”

## 1:35–1:55 · Poisoned instructions

“But what if the attacker poisons the instructions? This forged document claims security approved shutting down the payment records.

“Precedent checks who supplied it and whether it was independently verified. The claim inside the document is not enough. The action is rejected.”

## 1:55–2:35 · Learning and practical impact

“After recovery passes independent checks, Precedent saves a verified lesson. Now a fresh Qoder session faces another incident. It finds that new lesson, cites it, and recovers again.

“It still checks today’s conditions. A missing control or failed backup leads to a different decision, rather than blindly repeating yesterday’s fix.

“For security and operations teams, that means a way to test AI responders before giving them wider responsibility: preserve service, reject bad instructions, and inspect what happened. This demo proves that loop in a controlled environment.”

## 2:35–2:40 · Close

“Precedent: agents that learn from experience, with evidence before action.”

## Why this fits the judging criteria

| Criterion                         | What the recording demonstrates                                                                                     |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| AI and Qoder — 25% / 25%          | Actual Qoder investigation, revised proposal, tool execution, and fresh-session reuse.                              |
| Execution and craft — 25% / 20%   | Working HTTP services, independently checked outcomes, enforced approvals, receipts, and inspectable reports.       |
| Innovation — 20% / 20%            | Verified experience changes the next response; source authority and current conditions remain part of the decision. |
| Real-world impact — 15% / 20%     | A concrete problem for security and operations teams: responding to attacks without avoidable service disruption.   |
| Demo and storytelling — 15% / 15% | Problem → intervention → proof → poisoned instructions → learning. One continuous story within three minutes.       |

The supplied weights are Builder / Creator. Do not claim production deployment, real customer payments, or Qoder development review. Historical cases are fictional. The runtime actions and requests are real within the local demonstration.
