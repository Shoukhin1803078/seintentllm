# SentinelLLM — Person 2 (AI, ML & Multimodal Security Analyst)

**Progress report**
**Prepared:** 2026-10-12
**Scope:** everything downstream of Person 1's collector — feature extraction, ML baselines, evaluation, and the abuse.ch threat-intelligence layer.

---

## 1. Summary

The AI pipeline runs end to end and is reproducible with one command (`make reproduce`), built against **synthetic data generated from a schema contract we own** rather than waiting on Person 1's collector.

This period added a **real threat-intelligence layer** (abuse.ch: MalwareBazaar, ThreatFox, URLhaus) that grounds the pipeline's indicators in live data.

**Headline result — unchanged and now quantified.** Synthetic data validates the pipeline but **cannot evidence the detection claims**. Random Forest reaches **F1 = 1.000** on a chronological split; hold out entire attack *families* and it collapses to **F1 = 0.072 while flagging 41% of benign activity**. Template-generated data is separable by construction. Real benign telemetry is a prerequisite for the proposal's §10 and §18 claims, not an optional extra.

**New result from real intel.** Live abuse.ch data is a **clean signal on file hashes** (0 benign false matches) and a **poor signal on domains** — 82% of benign incidents matched a known-bad domain, every one on `github.com`, because legitimate infrastructure is abused. "Domain is on a blocklist" is a false-positive generator.

---

## 2. Data

### 2.1 Synthetic corpus (v0.3.0 / v0.4.0)

| Metric | Value |
|---|---|
| Incidents | 800 |
| Events | 22,964 (median 28 per incident; range 7–64) |
| Labels | benign 506 · suspicious 58 · malicious 236 |
| Scenario families | 14 (4 malicious, 9 benign incl. **6 hard negatives**, 1 ambiguous) |
| Hard negatives | 381 |
| Benign incidents firing ≥1 rule | 55.9% |
| Malicious incidents firing no rule | 1.7% |
| Features | 58 in 7 groups (63 in 8 groups with `intel`) |

The generator is deterministic from a seed. Six benign families are **hard negatives** — benign activity that fires attack rules (signed updaters staging in Temp, portable password managers reading credential stores, genuine CAPTCHA pages, cloud sync with high egress, PUA false alarms).

### 2.2 Real threat intelligence (abuse.ch)

Pulled live from three community feeds:

| Feed | Entries | Contributes |
|---|---|---|
| MalwareBazaar | 1,000 samples | file hashes, family, ClamAV, code-signing certs |
| ThreatFox | 8,987 IOCs | C2 domains, IPs, URLs, malware family, confidence |
| URLhaus | 32,834 URLs | malware-distribution hosts |

Normalised index: **11,246 domains · 781 IPs · 3,168 hashes**.

### 2.3 Split policies

| Policy | Use |
|---|---|
| `time` | default; chronological, realistic deployment setting |
| `family` | leave-scenario-families-out; strictest generalisation test |
| `random` | reference only — inflated, included to quantify leakage |

---

## 3. Method

- **Features**: incident-level, organised into selectable groups (`rules static temporal graph network visual corroboration`), so an ML configuration can be trained with *or without* rule-derived features. Without this, "ML only" and "Rules only" measure the same thing and the ablation is vacuous.
- **Baselines**: Logistic Regression, Random Forest, and a deterministic rules-only scorer implementing the proposal's §8 weights verbatim.
- **Metrics**: precision, recall, F1, PR-AUC, FPR, and `hard_negative_fpr` (FPR restricted to benign-but-suspicious activity) as a first-class metric.
- **Every run** appends to `reports/experiments.csv` (seed, split, feature groups, dataset version, all metrics). **43 runs logged.**

The new intel layer adds two things: `generate.py --intel` replaces malicious C2 domains and payload hashes with real abuse.ch indicators, and `features.py --intel` adds an opt-in `intel` feature group. The default pipeline is unchanged without the flag.

---

## 4. Results

### 4.1 Detection (v0.3.0, 240 test incidents)

**Chronological split (`time`) — the headline numbers**

| Configuration | P | R | F1 | PR-AUC | FPR |
|---|---|---|---|---|---|
| RF · all features | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |
| RF · non-rule features | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 |
| LR · non-rule features | 1.000 | 0.933 | 0.966 | 0.996 | 0.000 |
| LR · rule features | 1.000 | 0.800 | 0.889 | 0.950 | 0.000 |
| Rules only (§8 weights) | 1.000 | 0.387 | 0.558 | 0.790 | 0.000 |

**Leave-families-out (`family`) — the honest numbers**

| Configuration | P | R | F1 | FPR |
|---|---|---|---|---|
| LR · rule features | 1.000 | 0.192 | 0.323 | 0.000 |
| RF · non-rule features | 0.083 | 0.064 | 0.072 | 0.410 |
| RF · all features | 0.043 | 0.051 | 0.046 | 0.672 |
| Rules only (§8) | 0.000 | 0.000 | 0.000 | 0.000 |
| LR · non-rule features | 0.000 | 0.000 | 0.000 | 0.433 |

Reading: the chronological column is the synthetic corpus being linearly separable, not detection. Under family holdout every learned configuration is at or below chance (F1 ≤ 0.072) and flags 41–67% of benign traffic. The rules-only baseline keeps precision 1.000 but misses 61% of attacks on the chronological split and everything on the family split.

### 4.2 Real intelligence signal (v0.4.0)

| | malicious (236) | benign (506) | suspicious (58) |
|---|---|---|---|
| Matched a known-bad **hash** | 196 (83%) | **0** | **0** |
| Matched a known-bad **domain** | 219 (93%) | **414 (82%)** | 44 (76%) |

Adding the `intel` feature group changed nothing in the model (RF F1 = 1.000 with and without it) — the corpus is already separable without it.

---

## 5. Findings

1. **Synthetic separability is the dominant threat to validity.** RF reaches F1 = 1.000 across three generator versions, including after two deliberate confound removals. No metric computed on this corpus can support a detection claim.

2. **Generalisation to unseen attack types is the real test, and it fails.** With only four malicious families, leave-families-out is near-degenerate — the model cannot be honest about attacks it has not been shown.

3. **The §8 rule weights trade recall for clean false positives.** Precision 1.000 and FPR 0.000, but 61% of attacks missed. Two §8 defects are documented in `docs/threat_model_ai.md`: allowlist suppression and a §7/§8 scoring disagreement.

4. **Real threat intel is a clean signal on hashes, not on domains.** Known-bad file hashes never matched benign activity. Known-bad domains matched 82% of benign incidents, all on `github.com` — legitimate infrastructure is listed by URLhaus because attackers abuse it. This is the reputable-hosting / allowlist-suppression failure, now measured on real data.

---

## 6. Limitations

- **No real benign telemetry.** The false-positive rate — the metric the proposal commits to measuring — cannot be validated on synthetic data. This is the single blocking dependency.
- Only **4 malicious families**; family-holdout generalisation numbers are pessimistic but unstable.
- The intel experiments depend on a **live index snapshot** and are a record, not a byte-reproducible result. ThreatFox IOCs also expire after 6 months.
- Figures 02/04/05 rely on a historical feature table (`features_v2.csv`) that predates the confound fix and cannot be regenerated from current code.

---

## 7. Next steps

**Blocked on Person 1 — escalate**
- Real benign capture (hours of ordinary use) — required for any FPR claim.
- More attack-chain variants — makes leave-families-out meaningful.
- `rules/rules.md` — stable rule-ID definitions; changing a rule invalidates every logged experiment.

**Not blocked — buildable now**
- Risk-fusion module (with the §8 allowlist defect fixed) and probability calibration.
- LLM analyst with grounding validation (every claim cites event IDs).
- Prompt-injection evaluation suite (our addition; strongest novelty angle).
- VLM screenshot benchmark and multimodal fusion.
- Dashboard (FastAPI + UI).

---

## References

- `reports/findings_week1.md` — written analysis behind the figures
- `reports/ablation.md` — results as a table, generated from the log
- `reports/experiments.csv` — append-only run log (43 runs)
- `docs/schema.md` — the Person 1 ↔ Person 2 data contract
- `docs/intel.md` — abuse.ch layer: rationale, mapping, limits
- `docs/threat_model_ai.md` — prompt injection, allowlist suppression, screenshot privacy
- `results/README.md` — figure guide; `results/figures/06_intel_signal.png` is the new intel figure
- `STATUS.md` — full done/remaining breakdown
