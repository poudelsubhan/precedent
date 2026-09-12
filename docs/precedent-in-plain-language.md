# What Precedent does

Precedent helps an AI agent make decisions by checking what is happening now against lessons from earlier incidents. It looks at which services depend on each other, what policies require, where evidence came from, and whether a previous response worked.

Imagine an attacker steals a key used by a payments system. An agent might cancel that key. That stops the attacker, but it also stops customers from paying if the payment services still need it.

Precedent checks the proposed action before it runs. It can allow it, reject it, suggest a safer sequence, or ask for human attention when information or controls are missing. In this example, it can require the services to move to a replacement key and pass real payment checks before the old key is cancelled.

The console shows the proposal, the decision, the evidence behind it, and the result. A separate execution service enforces each approval. A document cannot gain authority just by claiming that someone approved it.

After recovery, independent checks confirm that payments work and the attacker is blocked. Only then is the successful response saved as a verified lesson that another agent can use during a future incident, while checking current conditions again.
