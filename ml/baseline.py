"""Baseline models + leakage-aware evaluation + experiment log for SentinelLLM.

Implements three things the guide and proposal both require but do not specify:

1. Three split policies, so the leakage warning in guide section 14 becomes a
   measurement rather than a caveat:
       random  - stratified random split (INFLATED; reference only)
       time    - chronological split (default; realistic deployment setting)
       family  - leave-scenario-families-out (strictest generalisation test)
2. A deterministic rules-only baseline using the illustrative weights from
   proposal section 8, so "Rules only" in the ablation is a real comparator.
3. Feature-group selection, so an ML configuration can exclude rule-derived
   features and demonstrate information beyond the rule engine.

Every run appends one row to reports/experiments.csv with seed, split policy,
feature groups, model, data version and all metrics (guide section 4).

Usage
    python ml/baseline.py --split time --groups static,temporal,graph,network,visual
    python ml/baseline.py --split time --groups all --model rf
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis.features import all_groups, columns_for  # noqa: E402

EXPERIMENT_LOG = Path("reports/experiments.csv")

# Proposal section 8, verbatim. Illustrative, not tuned - that is the point of
# having them here: the ablation measures what these hand weights achieve.
RULE_WEIGHTS = {
    "rules__R003": 15,   # unsigned executable from Temp
    "rules__R001": 15,   # hidden PowerShell
    "rules__R002": 10,   # ExecutionPolicy bypass
    "rules__R004": 15,   # remote script download
    "rules__R005": 10,   # password-protected archive staging
    "rules__R006": 20,   # browser credential-store access
    "rules__R007": 15,   # rare outbound destination
    "rules__R008": 10,   # persistence Run key (not weighted in s8; conservative)
    "rules__R009": 5,
    "rules__R010": 5,
    "rules__R011": 10,
    "rules__R012": 5,
}
AV_CORROBORATION_WEIGHT = 40
TRUSTED_SIGNATURE_CREDIT = -30
ALLOWLIST_CREDIT = -50
RISK_BANDS = [(0, 19, "Normal"), (20, 39, "Observe"), (40, 59, "Suspicious"),
              (60, 79, "High"), (80, 100, "Critical")]


def rules_only_score(df: pd.DataFrame) -> np.ndarray:
    """Deterministic risk score per proposal section 8, clamped to [0, 100]."""
    s = np.zeros(len(df), dtype=float)
    for col, w in RULE_WEIGHTS.items():
        if col in df:
            s += df[col].to_numpy() * w
    if "corroboration__any_malicious_verdict" in df:
        s += df["corroboration__any_malicious_verdict"].to_numpy() * AV_CORROBORATION_WEIGHT
    # Trusted-signature credit: applied when NO untrusted-signer process is present.
    if "static__n_untrusted_signer_proc" in df:
        s += (df["static__n_untrusted_signer_proc"].to_numpy() == 0) * TRUSTED_SIGNATURE_CREDIT
    return np.clip(s, 0, 100)


def band(score: float) -> str:
    for lo, hi, name in RISK_BANDS:
        if lo <= score <= hi:
            return name
    return "Critical"


def make_split(df: pd.DataFrame, policy: str, seed: int, test_size: float = 0.3):
    """Returns (train_idx, test_idx). Grouping prevents near-duplicate leakage."""
    if policy == "random":
        tr, te = train_test_split(df.index.to_numpy(), test_size=test_size,
                                  random_state=seed, stratify=df["y"])
        return tr, te
    if policy == "time":
        order = df.sort_values("start_time").index.to_numpy()
        cut = int(len(order) * (1 - test_size))
        return order[:cut], order[cut:]
    if policy == "family":
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        tr, te = next(gss.split(df, df["y"], groups=df["scenario_family"]))
        return df.index.to_numpy()[tr], df.index.to_numpy()[te]
    raise ValueError(f"unknown split policy: {policy}")


def metrics(y_true, y_pred, y_score, hard_mask) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }
    if y_score is not None and len(set(y_true)) > 1:
        out["pr_auc"] = average_precision_score(y_true, y_score)
        out["roc_auc"] = roc_auc_score(y_true, y_score)
    else:
        out["pr_auc"] = float("nan")
        out["roc_auc"] = float("nan")
    # The metric that actually matters operationally: how often do we flag benign
    # activity that *looks* like the attack? (proposal section 10, remediation safety)
    hn = np.asarray(hard_mask, dtype=bool) & (np.asarray(y_true) == 0)
    out["hard_negative_fpr"] = (
        float(np.asarray(y_pred)[hn].mean()) if hn.sum() else 0.0)
    out["n_hard_negatives"] = int(hn.sum())
    return out


def build_model(name: str, seed: int):
    if name == "lr":
        return Pipeline([("scale", StandardScaler()),
                         ("clf", LogisticRegression(max_iter=2000, class_weight="balanced",
                                                    random_state=seed))])
    if name == "rf":
        return RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                      class_weight="balanced_subsample",
                                      random_state=seed, n_jobs=-1)
    if name == "rules":
        return None
    raise ValueError(name)


def log_experiment(row: dict) -> None:
    EXPERIMENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    exists = EXPERIMENT_LOG.exists()
    with EXPERIMENT_LOG.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(row))
        if not exists:
            w.writeheader()
        w.writerow(row)


def run(features: Path, model_name: str, groups: list[str], split: str,
        seed: int, threshold: float, data_dir: Path, note: str) -> dict:
    df = pd.read_csv(features)
    df = df.reset_index(drop=True)
    groups = all_groups(df) if groups == ["all"] else groups
    cols = columns_for(df, groups)
    if not cols and model_name != "rules":
        raise SystemExit(f"no features for groups {groups}")

    tr, te = make_split(df, split, seed)
    ytr, yte = df.loc[tr, "y"].to_numpy(), df.loc[te, "y"].to_numpy()
    hard = df.loc[te, "is_hard_negative"].to_numpy()

    if model_name == "rules":
        score = rules_only_score(df.loc[te])
        pred = (score >= 60).astype(int)          # High band and above
        score_for_auc = score / 100.0
        feat_desc = "proposal_s8_weights"
    else:
        Xtr, Xte = df.loc[tr, cols].to_numpy(), df.loc[te, cols].to_numpy()
        m = build_model(model_name, seed)
        m.fit(Xtr, ytr)
        score_for_auc = m.predict_proba(Xte)[:, 1]
        pred = (score_for_auc >= threshold).astype(int)
        feat_desc = ",".join(groups)

    mt = metrics(yte, pred, score_for_auc, hard)
    manifest = json.loads((data_dir / "manifest.json").read_text())
    cfg = {
        "run_id": hashlib.sha256(
            f"{model_name}{groups}{split}{seed}{threshold}{manifest['seed']}".encode()
        ).hexdigest()[:12],
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": model_name,
        "feature_groups": feat_desc,
        "n_features": len(cols) if model_name != "rules" else len(RULE_WEIGHTS),
        "split_policy": split,
        "seed": seed,
        "threshold": threshold,
        "data_version": manifest["generator_version"],
        "data_seed": manifest["seed"],
        "n_incidents": manifest["n_incidents"],
        "n_train": len(tr),
        "n_test": len(te),
        "python": platform.python_version(),
        "note": note,
    }
    log_experiment({**cfg, **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in mt.items()}})
    return {**cfg, **mt}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--features", type=Path, default=Path("reports/features.csv"))
    p.add_argument("--data", type=Path, default=Path("data_synthetic/v1"))
    p.add_argument("--model", default="lr", choices=["lr", "rf", "rules"])
    p.add_argument("--groups", default="all",
                   help="comma-separated feature groups, or 'all'")
    p.add_argument("--split", default="time", choices=["random", "time", "family"])
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--note", default="")
    a = p.parse_args()
    r = run(a.features, a.model, a.groups.split(","), a.split, a.seed,
            a.threshold, a.data, a.note)
    keys = ["model", "feature_groups", "split_policy", "precision", "recall", "f1",
            "pr_auc", "fpr", "hard_negative_fpr", "tp", "fp", "fn", "tn"]
    print(json.dumps({k: (round(r[k], 4) if isinstance(r[k], float) else r[k]) for k in keys}, indent=2))


if __name__ == "__main__":
    main()
