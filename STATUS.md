# SentinelLLM — Person 2 Status

**Role:** AI, ML & Multimodal Security Analyst
**Scope:** everything downstream of Person 1's collector — features, ML, LLM analyst, VLM detector, risk fusion, dashboard, evaluation
**Last updated:** 2026-10-10
**Branch:** `main` (work should move to `person2-ai` per guide §4)

---

## 1. Where the project stands

The AI pipeline runs end to end and is reproducible with one command
(`make reproduce`). It is built against **synthetic data generated from a schema
contract we own**, rather than waiting on Person 1's collector.

**Headline result:** synthetic data validates the pipeline but **cannot evidence
the detection claims**. Random Forest reaches F1 = 1.000 on a chronological split
across three generator versions, including after two deliberate confound
removals. Template-generated data is separable by construction. Real benign
telemetry is a prerequisite for the proposal's §10 and §18 claims, not an
optional extra. Full argument: `reports/findings_week1.md`.

---

## 2. Done

### Infrastructure
- [x] Repo structure, venv, pinned deps, `.gitignore`, `Makefile`
- [x] `make reproduce` — data → features → conformance tests → baselines
- [x] Append-only experiment log (`reports/experiments.csv`) — seed, split policy,
      feature groups, data version, all metrics. **28 runs logged.**

### Data contract
- [x] `ml/schema/events.v1.json` — 16 event types, process/file/registry/network/
      credential/visual/detection blocks, ATT&CK technique IDs
- [x] `ml/schema/incidents.v1.json` — incident grouping, labels, scenario family
      as split key, stage-level ground truth
- [x] `docs/schema.md` — handoff document, **ready to send to Person 1**
- [x] Conformance tests: schema validity, referential integrity, privacy invariants

### Synthetic corpus (generator v0.3.0)
- [x] 14 scenario families, 800 incidents, ~23k events, deterministic by seed
- [x] 4 malicious families incl. `lotl_credential_theft` (signed binaries, legit-infra C2)
- [x] **6 hard-negative benign families** — benign activity that fires attack rules
- [x] 5 evasion dimensions: signed payloads, reputable-hosting C2, slow dwell,
      low-volume exfil, absent AV corroboration
- [x] `--ambiguity` flag; difficulty reported in the manifest
- [x] Two generator confounds found and fixed (event count, dwell time)

### Modelling & evaluation
- [x] `analysis/features.py` — 58 features in **7 selectable groups**
- [x] Logistic Regression and Random Forest baselines
- [x] Deterministic rules-only baseline implementing **proposal §8 weights verbatim**
- [x] Three split policies: `time`, `family`, `random`
- [x] `hard_negative_fpr` as a first-class metric
- [x] `analysis/ablation_table.py` → `reports/ablation.md`
- [x] `analysis/make_figures.py` → `results/figures/` (5 figures)

### Analysis documents
- [x] `reports/findings_week1.md` — three findings, supervisor-ready
- [x] `docs/threat_model_ai.md` — prompt injection, allowlist suppression,
      screenshot privacy
- [x] `docs/features.md` — auto-generated feature dictionary

---

## 3. Remaining

Ordered by dependency. Weeks refer to the Person 2 guide §5.

### Blocked on Person 1 — escalate now
| Item | Why it blocks | Owner |
|---|---|---|
| **Real benign capture** (hours of ordinary use) | Only way to validate false-positive rate; proposal commits to measuring it | Person 1 |
| **More attack-chain variants** | Leave-families-out is near-degenerate with 4 malicious families | Person 1 |
| `rules/rules.md` — stable rule-ID definitions | Changing a rule's meaning invalidates every logged experiment | Person 1 |
| Confirmation that incident correlation is collector-side | Correlation is a stated research contribution (§7) | Person 1 |
| Quarantine result events | Dashboard cannot show response state without them | Person 1 |

### Not blocked — buildable now
| # | Item | Guide week | Notes |
|---|---|---|---|
| 1 | **Risk fusion module** | 5 | Fix the §8 allowlist-suppression defect first (`threat_model_ai.md` T3) |
| 2 | Probability calibration | 5 | Isotonic / Platt; calibration curves; currently uncalibrated |
| 3 | **LLM incident JSON + output schema** | 6 | `llm_schema.json`, prompts; every claim cites event IDs |
| 4 | **LLM analyst + grounding validator** | 7 | Reject unknown event IDs; measure unsupported-claim rate |
| 5 | **Prompt-injection evaluation suite** | 7 | Not in the proposal — our addition; strongest novelty angle |
| 6 | **VLM screenshot dataset** | 8 | Public/synthetic only; 7 classes; balanced manifest |
| 7 | VLM zero-shot / few-shot benchmark | 9 | Per-class P/R/F1 + confusion matrix |
| 8 | Multimodal fusion | 10 | Visual alert alone must never trigger deletion |
| 9 | **Dashboard (FastAPI + UI)** | 11 | Incident list, timeline, evidence cards, why-risk-is-high |
| 10 | Stronger model (XGBoost/LightGBM) | — | Only once the pipeline is correct; low priority given F1 ceiling |
| 11 | External baseline (Sigma rules / Defender) | 12 | **Reviewers will ask**; internal ablation alone is not enough |
| 12 | MITRE ATT&CK coverage table | 12 | Technique IDs already in the schema, unused so far |
| 13 | Final ablation + paper figures | 12 | Table generator exists; needs the remaining configurations |

### Open decisions for the supervisor
1. **Timeline conflict.** Guide = 12 weeks, proposal = 16. Guide has ML in week 3;
   proposal has the collector finishing week 4 and rules week 6. Needs one schedule.
2. **Detection claims on synthetic data.** Either obtain real data or state the
   limitation explicitly in the paper. Current evidence says the latter is not enough
   for the headline claim.
3. **Unowned components.** Sandbox (CAPE/Cuckoo) and reputation/threat intelligence
   appear in proposal §6.4/§9/§12 and in the final ablation row, but have no owner
   and no directory. Assign or cut.
4. **Account correlation** (§3, §4, §19) — depends on third-party APIs that mostly
   do not expose this. Recommend cutting to a stated limitation.
5. **`LLM only` ablation config** is in the proposal (§11) but missing from the
   guide (§12). It is the row that justifies the architecture — keep it.

---

## 4. Key numbers

| Metric | Value | Source |
|---|---|---|
| Synthetic incidents / events | 800 / 22,964 | `data_synthetic/v3/manifest.json` |
| Scenario families (malicious / benign / ambiguous) | 4 / 9 / 1 | manifest |
| Benign incidents firing ≥1 rule | 55.9% | manifest — rules-only FP ceiling |
| Malicious incidents firing no rule | 1.7% | manifest — what ML must catch |
| §8 rules-only (chronological) | P 1.000 · R 0.387 · FPR 0.000 | `reports/ablation.md` |
| Best ML (chronological) | F1 1.000 | **not trustworthy — see findings** |
| Best ML (leave-families-out) | F1 0.072 · FPR 0.410 | the honest generalisation number |
| Experiment runs logged | 28 | `reports/experiments.csv` |

---

## 5. Reproduce

```bash
make setup
make reproduce
python analysis/ablation_table.py --data-version 0.3.0
python analysis/make_figures.py
```
