# Ablation results

Source: `reports/experiments.csv` · generator version: `0.3.0` · n_test per row in the log.

## Split: `time`

chronological split — the headline numbers

| Configuration | P | R | F1 | PR-AUC | FPR | FPR_hard |
|---|---|---|---|---|---|---|
| `rf / corroboration,graph,network,rules,static,temporal,visual` | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `rf / static,temporal,graph,network,visual,corroboration` | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `lr / static,temporal,graph,network,visual,corroboration` | 1.000 | 0.933 | 0.966 | 0.996 | 0.000 | 0.000 |
| `lr / rules` | 1.000 | 0.800 | 0.889 | 0.950 | 0.000 | 0.000 |
| `rules / proposal_s8_weights` | 1.000 | 0.387 | 0.558 | 0.790 | 0.000 | 0.000 |

## Split: `family`

leave-scenario-families-out — generalisation to unseen attack types

| Configuration | P | R | F1 | PR-AUC | FPR | FPR_hard |
|---|---|---|---|---|---|---|
| `lr / rules` | 1.000 | 0.192 | 0.323 | 0.434 | 0.000 | 0.000 |
| `rf / static,temporal,graph,network,visual,corroboration` | 0.083 | 0.064 | 0.072 | 0.277 | 0.410 | 0.410 |
| `rf / corroboration,graph,network,rules,static,temporal,visual` | 0.043 | 0.051 | 0.046 | 0.235 | 0.672 | 0.672 |
| `rules / proposal_s8_weights` | 0.000 | 0.000 | 0.000 | 0.312 | 0.000 | 0.000 |
| `lr / static,temporal,graph,network,visual,corroboration` | 0.000 | 0.000 | 0.000 | 0.306 | 0.433 | 0.433 |

