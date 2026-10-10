# SentinelLLM — Person 2 (AI, ML & Multimodal Security Analyst)

Downstream half of SentinelLLM: turns Person 1's endpoint evidence into scored,
explained, auditable incidents. See `SentinelLLM_Project_Proposal.pdf` and
`SentinelLLM_Person2_AI_Multimodal_Guide.docx`.

## Quick start

```bash
make setup      # venv + deps
make reproduce  # generate data -> features -> conformance tests -> baselines
```

Or activate the venv and work interactively:

```bash
source .venv/bin/activate
```

## Why synthetic data first

The roadmap has ML baselines in week 3 but the collector finishing week 4 and the
rule engine week 6. Rather than wait, this half defines the **event schema as a
contract** (`docs/schema.md`) and generates conforming synthetic data, so the whole
pipeline is built and evaluated before real telemetry exists. When the collector
lands, the data source swaps and nothing else changes.

It also fixes a sample-size problem: the guide asks Person 1 for "at least three
synthetic attack-chain scenarios", which cannot support PR-AUC, calibration, or
family-separated splits. The generator produces hundreds of varied incidents,
including **hard negatives** — benign activity that fires attack rules (signed
updaters staging in Temp, dev toolchains running unsigned binaries, genuine
CAPTCHA pages, legitimate hidden PowerShell automation). Those drive the
false-positive rate the proposal commits to measuring.

**Limitation, stated up front:** synthetic data cannot validate false-positive rate
on real benign activity. That requires a real benign capture from Person 1.

## Layout

| Path | Contents |
|---|---|
| `ml/schema/` | versioned JSON Schema — the Person 1 ↔ Person 2 contract |
| `data_synthetic/generate.py` | deterministic event generator, 10 scenario families |
| `analysis/features.py` | incident-level features in 7 selectable **groups** |
| `ml/baseline.py` | LR / RF / rules-only baselines, 3 split policies, experiment log |
| `tests/` | schema conformance + referential integrity + privacy invariants |
| `docs/schema.md` | the handoff contract |
| `docs/threat_model_ai.md` | prompt injection, allowlist suppression, screenshot privacy |
| `reports/experiments.csv` | append-only log: seed, split, groups, data version, metrics |

## Feature groups

`rules static temporal graph network visual corroboration`

Group selection is what makes the ablation meaningful. If the ML model is trained
only on rule-derived features, then "ML only" and "Rules only" in the proposal's
ablation (§11) measure the same thing. Training on the non-rule groups tests
whether a learned model carries information the deterministic engine lacks.

```bash
python ml/baseline.py --model rf --groups static,temporal,graph,network --split time
```

## Split policies

| Policy | Use |
|---|---|
| `time` | default; chronological, realistic deployment setting |
| `random` | reference only — **inflated**, included to quantify leakage |
| `family` | leave-scenario-families-out; strictest generalisation test |

Running all three turns the guide's leakage warning (§14) into a measurement.

## Status

Built: schema contract, generator (v0.3.0, 14 scenario families), feature
pipeline, conformance tests, LR/RF and §8 rules-only baselines, experiment
logging, ablation table generator.

**Read `reports/findings_week1.md` before trusting any metric.** Headline result:
synthetic data is separable by construction (RF F1 = 1.000 even after removing
two confounds), so it validates the pipeline but cannot evidence the detection
claims. Real benign telemetry is a prerequisite, not a nice-to-have.

Next: risk fusion with the §8 allowlist-suppression defect fixed, LLM analyst
with grounding validation, VLM screenshot benchmark, dashboard.
