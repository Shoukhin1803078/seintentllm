# AI-Layer Threat Model

Person 2's components are themselves attack surface. The proposal's risk register
(s16) covers hallucination, VLM misreads and overhead, but not adversarial
manipulation of the AI layer. This file tracks that gap.

## T1 - Indirect prompt injection via evidence fields

**Vector.** `process.cmdline`, `file.path` and `visual.page_text_excerpt` are
attacker-controlled and flow into the LLM analyst's context. An attacker can name
a file to carry instructions, or place text on a deceptive page that the VLM
transcribes into the pipeline.

**Why schema-constrained output is not a mitigation.** Constraining the output
*shape* does not protect the *premise*. A model that obediently emits
`{"hypothesis": "benign", "supporting_evidence": ["E101"]}` is well-formed and
wrong.

**Mitigations.**
- Delimit and escape untrusted fields on the way into any prompt; label them as
  untrusted data in the prompt itself.
- Validate every cited `event_id` against the incident's actual event set; reject
  outputs citing unknown IDs (already required by proposal s6.6).
- Cap influence: the LLM is advisory. A deterministic policy engine decides
  high-impact actions (proposal s5 safety boundary), so a successful injection
  degrades explanation quality but cannot trigger deletion.
- **Evaluate it.** Add an injection suite to the benchmark: N incidents with
  instruction-carrying filenames, command lines and page text. Report
  attack-success rate alongside the hallucination rate.

## T2 - Evasion of the learned detector

Renaming, signing with an untrusted-but-valid certificate, slowing the chain to
defeat latency features, padding with benign noise. Partly covered by the
proposal's adversarial-robustness experiment (s9), which currently targets the
detector only.

## T3 - Allowlist suppression

Proposal s8 gives known-good-hash a `-50` credit while independent AV/YARA
corroboration is only `+40`. An allowlisted binary that is in fact malicious
(supply-chain compromise, hash collision) nets negative and is suppressed.

**Fix:** independent corroboration must not be suppressible by allowlist credit -
apply a floor, or make AV/YARA agreement override the credit rather than sum with it.

## T4 - Screenshot capture as a privacy surface

`visual.capture_trigger = high_risk_navigation` means the deployed system
screenshots live browser windows. Proposal s15 forbids storing raw credentials but
a screenshot of a login page captures them as pixels, outside every listed control.

**Required policy:** capture only on trigger, process in-memory, never persist
alongside events, redact input-field regions before inference, and run inference
locally. If any screenshot can reach a hosted API model, that needs explicit
ethical review.
