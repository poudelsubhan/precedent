# Precedent design decisions

The supplied Assay reference documents informed interaction and implementation principles, not Precedent’s brand, domain rules, framework, or workflow. Precedent remains an incident-response console.

## Visual identity

Graphite surfaces provide a quiet command workspace. Cobalt identifies controls and selection, violet identifies historical context, and red, amber, and green carry operational meaning. Labels accompany state. The palette belongs to Precedent and does not copy Assay’s paper-like visual identity.

Tokens live in `apps/console/app/globals.css`. Graph nodes use these tokens. Text uses tabular figures, readable secondary labels, and explicit probe timestamps. Glows and continuous edge animation are removed. Reduced-motion and forced-color preferences are supported.

## Three primary actions

Launch a response, replay H41, and compare responses are the three primary controls. Forged-evidence injection and topology reset are disclosed in a secondary group. The frequent evidence path is select decision → Show me why → inspect paths or sources. Three is a focus discipline, not a universal click limit.

## Evidence and honest state

History links use returned path IDs instead of invented case-to-case relationships. A replacement credential is not called verified just because of its name. No receipt means no receipt, not proof of completed execution. Unknown topology does not appear healthy. Probe results have timestamps and are scoped to the latest live run; comparison results are labeled separately.

New decisions retain immutable snapshots, query text, parameters, lineage paths, and policy versions. Legacy traces are labeled. A selected-decision export and a separate complete durable run export make their scope explicit. Request counters show their observation window and refresh every two seconds. SDK telemetry is available on demand so operational events remain readable.

## Frontend behavior

Shared contracts validate events and evaluation payloads. One response adapter validates endpoint data and provides bounded requests and readable failures. Latest-request ownership prevents obsolete responses from replacing current state. Manual decision selection stays stable during incoming events.

Native buttons and disclosure controls support keyboard use. Focus is visible, pending actions and failures are announced, graph tabs expose selection, and the graph has a text alternative. A render-error fallback provides a retry path.

The app retains Next.js and its current bundler. Assay’s Vite-specific guidance, tax evidence rules, keyboard map, precise row dimensions, and signed-memo workflow do not apply here.
