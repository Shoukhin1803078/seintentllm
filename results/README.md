# Results

Figures and analysis outputs for Person 2's half of SentinelLLM. Regenerate with:

```bash
python analysis/make_figures.py
```

All figures are generated from `reports/experiments.csv` and the feature tables —
no hand-edited values. Palette is a CVD-validated 3-slot categorical set; every
bar carries a direct value label.

## Figures

### `figures/01_ablation_f1_fpr.png`
Ablation across five configurations, under two split policies. **The story:** on a
chronological split everything looks excellent (RF F1 = 1.000); hold out entire
attack families and every learned configuration collapses to F1 < 0.08 while
flagging 41–67% of benign activity. The rules-only baseline keeps precision 1.000
throughout. This is the single most important figure in the set.

### `figures/02_generator_confounds.png`
Why the perfect scores were not real. Class-mean ratio (malicious ÷ benign) for
three features, before and after the v0.3.0 fix. Incident duration leaked at
**211×** because dwell-time scaling had been applied only to attack families — the
model was fingerprinting the generator, not detecting attacks. Both confounds now
sit near parity, *and the perfect scores survived*, which is the finding.

### `figures/03_rules_only_tradeoff.png`
Proposal §8's illustrative weights implemented verbatim and thresholded at the
High band (≥60). Precision 1.000 and FPR 0.000 across 506 benign incidents, but
recall only 0.387 — **61% of attacks missed**. The evasion variants introduced in
v0.2.0 cost the rule engine a further 7 points of recall.

### `figures/04_feature_importance.png`
Top non-rule features by Gini importance. Useful for sanity-checking what the
model attends to; **not** evidence about real telemetry, since the corpus is
synthetic.

### `figures/05_dataset_composition.png`
The v0.3.0 corpus: 800 incidents across 14 scenario families. Six benign families
are hard negatives — benign activity that fires attack rules (signed updaters
staging in Temp, portable password managers reading credential stores, genuine
CAPTCHA pages, PUA false alarms). 55.9% of benign incidents trip at least one rule.

## Related

- `reports/findings_week1.md` — written analysis behind these figures
- `reports/ablation.md` — the same results as a table, generated from the log
- `reports/experiments.csv` — append-only run log (28 runs)
- `STATUS.md` — what is done and what remains
