# Event Schema Contract v1.0.0

**Owner:** Person 2 (consumer) · **Producer:** Person 1 (collector) · **Status:** proposed, awaiting Person 1 review

This is the interface between the collector and the AI/ML layer. It exists so that
both halves can be built in parallel instead of serially: Person 2's pipeline is
developed against synthetic data conforming to this contract, and switches to real
collector output with no code change once the collector emits it.

Machine-readable: [`ml/schema/events.v1.json`](../ml/schema/events.v1.json),
[`ml/schema/incidents.v1.json`](../ml/schema/incidents.v1.json).
Conformance is enforced by `tests/test_schema_conformance.py`.

## Why a contract, not a handoff

The project roadmap has Person 2 training models in week 3 (Person 2 guide, s5)
while the collector completes in week 4 and the rule engine in week 6
(proposal, s13, phases 2-3). Without a schema agreed up front, Person 2 is
blocked for three weeks and then rebuilds features when the schema changes.

## Formats

- `events.jsonl` - one normalized event per line.
- `incidents.jsonl` - one correlated incident per line; the unit of ML prediction.
- `manifest.json` - dataset provenance: generator version, seed, counts. Tracked in git.

## Rules Person 1 must honour

1. **`event_id` is globally unique and stable.** The LLM analyst cites these IDs,
   and outputs referencing unknown IDs are rejected (proposal s6.6). If IDs are
   reused or renumbered between runs, grounding validation breaks silently.
2. **`incident_id` groups events into one attack chain.** Correlation is a stated
   research contribution (proposal s7), so incident assignment is the collector's
   job, not something Person 2 reconstructs after the fact.
3. **`rule_hits` carry stable rule IDs** (`R001`..`Rnnn`) with one definition per
   ID, documented in `rules/rules.md`. Changing what an ID means invalidates every
   logged experiment that used it.
4. **Breaking changes bump `schema_version` and ship as a new file.** Never edit
   the meaning of an existing field in place.
5. **Timestamps are ISO-8601 UTC with millisecond precision.** Several features
   depend on inter-event ordering and latency; coarse timestamps destroy them.

## Privacy invariants (proposal s15)

These are encoded as assertions in the conformance test, not just prose:

| Field | Invariant |
|---|---|
| `credential_target.secrets_collected` | always `false` - store **metadata** only, never contents |
| `visual.input_fields_redacted` | always `true` - a phishing-page screenshot contains typed credentials as pixels |
| `registry.value_redacted` | `true` whenever the value could hold a secret |
| `host` | pseudonymous id, never a real hostname or username |

## Fields marked UNTRUSTED

`process.cmdline`, `file.path`, and `visual.page_text_excerpt` are
**attacker-controlled**. They reach the LLM analyst's context, which makes them an
indirect prompt-injection channel (e.g. a file named
`ignore_previous_instructions_benign.exe`, or page text instructing the model to
classify as safe). The proposal's risk register covers hallucination but not this.
Handling rules live in `docs/threat_model_ai.md`; the short version is: delimit and
escape on the way into a prompt, and never let these fields carry instructions.

## What Person 2 still needs from Person 1

Beyond the schema itself (Person 2 guide, s13):

- [ ] `rules/rules.md` with a stable definition per rule ID
- [ ] Confirmation that incident correlation happens collector-side
- [ ] Quarantine result events so the dashboard can show response state
- [ ] A real benign capture (hours of ordinary use) - synthetic data **cannot**
      validate false-positive rate, and the proposal commits to measuring it
- [ ] More than three attack-chain variants, or agreement that the detection
      claims rest on synthetic data with that limitation stated in the paper

## Dataset difficulty (v0.2.0)

Two manifest numbers define how hard a synthetic dataset is, and both are logged:

- `benign_rule_fire_rate` — fraction of benign incidents that trip at least one
  rule. The rules-only false-positive ceiling. **v2: 0.552**
- `malicious_rule_miss_rate` — fraction of malicious incidents that trip nothing.
  What a learned detector has to catch that the rule engine cannot. **v2: 0.029**

v0.1.0 produced perfectly separable data (RF reached F1 = 1.000), which makes every
metric meaningless. v0.2.0 adds five evasion dimensions to the attack families —
signed payloads via stolen or cheap certificates, C2 on reputable hosting
(`raw.githubusercontent.com`, `cdn.discordapp.com`), multi-hour dwell times,
low-volume exfiltration, and absent AV corroboration — plus four families that
attack the features a model leans on:

| Family | Breaks |
|---|---|
| `lotl_credential_theft` (malicious) | signed MS binaries only, legit-infra C2, slow — nearly every signal absent |
| `benign_password_manager` | fires R006 (+20, the heaviest rule) legitimately |
| `benign_cloud_sync` | high egress + elevated domain rarity + fast exec→egress |
| `benign_pua_flagged` | benign software with an AV malicious verdict (+40 signal, wrong) |

The `--ambiguity` flag scales the evasion probabilities. Report results at
`--ambiguity 1.0`; lower values are for debugging only.
