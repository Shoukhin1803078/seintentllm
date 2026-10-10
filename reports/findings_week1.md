# Week 1 findings — Person 2 (AI/ML layer)

Generator versions 0.1.0 → 0.3.0, datasets v1–v3, 25 logged runs in
`reports/experiments.csv`. Table: `reports/ablation.md`.

## F1 — Synthetic data cannot validate the detection claims

Random Forest reaches **F1 = 1.000** on a chronological split at every generator
version, including v0.3.0 after two deliberate confound removals:

| Version | Change | RF (non-rule features), time split |
|---|---|---|
| 0.1.0 | baseline, 10 families | F1 1.000 |
| 0.2.0 | +5 evasion dimensions, +4 overlapping families, 14 total | F1 0.987 |
| 0.3.0 | label-independent noise volume and dwell time | F1 1.000 |

**Diagnosed cause.** At v0.2.0 the top RF features were generator artifacts, not
security signal:

| Feature | benign | malicious | Nature |
|---|---|---|---|
| `graph__n_proc_events` | 19.3 | 12.5 | per-family hard-coded noise ranges |
| `temporal__duration_s` | 403 | 85,058 | dwell-time scaling applied only to attacks |

Both were fixed in v0.3.0 (noise drawn from one label-independent distribution;
long sessions assigned regardless of label), bringing the means to 28.6 vs 25.7
and a 1.6× duration ratio. **Perfect separation survived the fix.**

**Conclusion.** Template-generated data is separable by construction: each class
is produced by a distinct generative process, so a sufficiently flexible model
recovers that process. Further tuning is not worth the effort.

**Consequence for the project.** The synthetic corpus is valid for (a) pipeline
development, (b) schema and conformance testing, (c) stress-testing the rule
engine, and (d) *relative* comparisons between configurations. It is **not** valid
evidence for the proposal's detection or false-positive claims (§10, §18). Those
require real benign telemetry and real attack captures. This limitation must be
stated in the paper rather than discovered at integration.

## F2 — No generalisation to unseen attack families

Leave-scenario-families-out (`--split family`):

| Configuration | P | R | F1 | FPR |
|---|---|---|---|---|
| `lr / rules` | 1.000 | 0.192 | 0.323 | 0.000 |
| `rf / non-rule features` | 0.083 | 0.064 | 0.072 | 0.410 |
| `rules / §8 weights` | 0.000 | 0.000 | 0.000 | 0.000 |

Held out an entire attack family, the learned models collapse and flag 41–67% of
benign activity. With four malicious families this split is near-degenerate — it
measures "can you detect an attack type you have never seen", and the honest
answer is no. **This is the number that matters for a deployment claim**, and it
argues for the rule engine making the first-pass decision exactly as the proposal
specifies (§7 of the guide).

## F3 — The §8 risk weights trade most of recall for a clean FP record

Implemented verbatim from proposal §8, thresholded at the High band (≥60):

| Dataset | Precision | Recall | FPR |
|---|---|---|---|
| v1 (no evasion) | 1.000 | 0.457 | 0.000 |
| v3 (full evasion) | 1.000 | 0.387 | 0.000 |

Zero false positives across 506 benign incidents — including 283 that fire at
least one rule — but **61% of attacks missed**. The evasion dimensions (signed
payloads, C2 on reputable hosting, living-off-the-land chains) cost the rule
engine a further 7 points of recall, confirming they bite.

Two defects found while implementing the weights:

1. **Allowlist suppression.** Known-good-hash credit (−50) exceeds independent
   AV/YARA corroboration (+40), so an allowlisted-but-malicious binary nets
   negative. Corroboration must not be suppressible — see `docs/threat_model_ai.md` T3.
2. **§7 and §8 disagree.** §7 marks "AV/YARA also detects payload" as Critical;
   under §8 arithmetic, +40 alone lands in Suspicious (40–59).

## Recommendations

1. **Escalate the real-data requirement now.** A benign capture (hours of ordinary
   use) and more attack variants are prerequisites for the headline claims, not
   nice-to-haves. Three synthetic scenarios cannot support PR-AUC or calibration.
2. **Report the `family` split as the primary generalisation metric**, with `random`
   shown only to quantify leakage.
3. **Position the ML layer as triage and calibration**, not as a detector competing
   with the rules — which is also what proposal §6.4 says it is for.
4. **Fix the two §8 defects** before the fusion module is built on those weights.
