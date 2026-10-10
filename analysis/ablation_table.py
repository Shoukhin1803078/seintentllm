"""Render reports/experiments.csv as the ablation table for the paper.

Reads the append-only experiment log and emits a markdown table per split
policy, so proposal s11's ablation ladder is generated from logged runs rather
than transcribed by hand.

Usage
    python analysis/ablation_table.py --data-version 0.2.0 --out reports/ablation.md
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

METRICS = ["precision", "recall", "f1", "pr_auc", "fpr", "hard_negative_fpr"]
LABELS = {"precision": "P", "recall": "R", "f1": "F1", "pr_auc": "PR-AUC",
          "fpr": "FPR", "hard_negative_fpr": "FPR_hard"}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--log", type=Path, default=Path("reports/experiments.csv"))
    p.add_argument("--data-version", default=None, help="filter to one generator version")
    p.add_argument("--out", type=Path, default=Path("reports/ablation.md"))
    a = p.parse_args()

    d = pd.read_csv(a.log)
    if a.data_version:
        d = d[d["data_version"].astype(str) == a.data_version]
    if d.empty:
        raise SystemExit("no matching experiment rows")
    # Keep the latest run per (config, split) so re-runs supersede cleanly.
    d["config"] = d["model"] + " / " + d["feature_groups"].astype(str)
    d = d.drop_duplicates(subset=["config", "split_policy"], keep="last")

    lines = ["# Ablation results", "",
             f"Source: `{a.log}` · generator version: "
             f"`{a.data_version or 'all'}` · n_test per row in the log.", ""]
    for sp in ["time", "family", "random"]:
        sub = d[d["split_policy"] == sp]
        if sub.empty:
            continue
        note = {"time": "chronological split — the headline numbers",
                "family": "leave-scenario-families-out — generalisation to unseen attack types",
                "random": "**inflated, reference only** — included to quantify leakage"}[sp]
        lines += [f"## Split: `{sp}`", "", note, "",
                  "| Configuration | " + " | ".join(LABELS[m] for m in METRICS) + " |",
                  "|" + "---|" * (len(METRICS) + 1)]
        for _, r in sub.sort_values("f1", ascending=False).iterrows():
            cells = " | ".join(f"{r[m]:.3f}" if pd.notna(r[m]) else "—" for m in METRICS)
            lines.append(f"| `{r['config']}` | {cells} |")
        lines.append("")
    a.out.write_text("\n".join(lines) + "\n")
    print(f"wrote {a.out} ({len(d)} configurations)")
    print("\n".join(lines[:40]))


if __name__ == "__main__":
    main()
