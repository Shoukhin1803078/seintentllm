"""Generate result figures for SentinelLLM Person 2 into results/figures/.

Static PNGs rather than interactive charts: these are destined for the repo and
the paper. Palette is the validated 3-slot categorical set (blue/orange/aqua);
every bar carries a direct value label, which is required because the aqua slot
sits below 3:1 contrast on the light surface.

Usage
    python analysis/make_figures.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

OUT = Path("results/figures")
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"   # categorical slots, fixed order
MUTED = "#9a9892"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "text.color": INK, "axes.labelcolor": INK2, "axes.edgecolor": GRID,
    "xtick.color": INK2, "ytick.color": INK2,
    "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "600",
    "axes.spines.top": False, "axes.spines.right": False,
    "grid.color": GRID, "grid.linewidth": 0.8,
    "figure.dpi": 150,
})


def _style(ax, xlabel=None, xlim=None):
    ax.grid(axis="x", alpha=0.7)
    ax.set_axisbelow(True)
    if xlabel:
        ax.set_xlabel(xlabel)
    if xlim:
        ax.set_xlim(*xlim)
    ax.tick_params(length=0)


def _labels(ax, bars, fmt="{:.3f}", pad=0.012):
    for b in bars:
        w = b.get_width()
        ax.text(w + pad, b.get_y() + b.get_height() / 2, fmt.format(w),
                va="center", ha="left", fontsize=8.5, color=INK2)


SHORT = {
    "rules / proposal_s8_weights": "Rules only (§8 weights)",
    "lr / rules": "LR · rule features",
    "lr / static,temporal,graph,network,visual,corroboration": "LR · non-rule features",
    "rf / static,temporal,graph,network,visual,corroboration": "RF · non-rule features",
    "rf / corroboration,graph,network,rules,static,temporal,visual": "RF · all features",
}


def fig_ablation(log: pd.DataFrame) -> None:
    """F1 and FPR per configuration, for the two meaningful split policies."""
    d = log[log["data_version"].astype(str) == "0.3.0"].copy()
    d["config"] = d["model"] + " / " + d["feature_groups"].astype(str)
    d = d[d["config"].isin(SHORT)]
    d = d.drop_duplicates(subset=["config", "split_policy"], keep="last")

    order = ["rules / proposal_s8_weights", "lr / rules",
             "lr / static,temporal,graph,network,visual,corroboration",
             "rf / static,temporal,graph,network,visual,corroboration",
             "rf / corroboration,graph,network,rules,static,temporal,visual"]
    order = [c for c in order if c in set(d["config"])]
    y = range(len(order))
    h = 0.38

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.4))
    for ax, metric, title in [(axes[0], "f1", "Detection quality (F1)"),
                              (axes[1], "fpr", "False-positive rate")]:
        tv = [d[(d.config == c) & (d.split_policy == "time")][metric].iloc[0] for c in order]
        fv = [d[(d.config == c) & (d.split_policy == "family")][metric].iloc[0] for c in order]
        b1 = ax.barh([i + h / 2 for i in y], tv, height=h, color=S1,
                     label="Chronological split", zorder=3)
        b2 = ax.barh([i - h / 2 for i in y], fv, height=h, color=S2,
                     label="Leave-families-out", zorder=3)
        _labels(ax, b1); _labels(ax, b2)
        ax.set_yticks(list(y))
        ax.set_yticklabels([SHORT[c] for c in order] if metric == "f1" else [])
        ax.set_title(title, loc="left", color=INK)
        _style(ax, xlim=(0, 1.18))
    axes[0].legend(frameon=False, loc="lower right", fontsize=9)
    fig.suptitle("Ablation: every configuration collapses on unseen attack families",
                 x=0.012, ha="left", fontsize=13, fontweight="600", color=INK)
    fig.text(0.012, 0.005,
             "Dataset v0.3.0 · 800 synthetic incidents · chronological split holds all families in train and test; "
             "leave-families-out withholds entire attack types.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.tight_layout(rect=(0, 0.035, 1, 0.93))
    fig.savefig(OUT / "01_ablation_f1_fpr.png", bbox_inches="tight")
    plt.close(fig)
    print("01_ablation_f1_fpr.png")


def fig_confound() -> None:
    """Class-mean ratio per leaked feature, before and after the confound fix.

    A ratio of 1.0 means the feature carries no label information from the
    generator's construction. Small multiples rather than one log axis: the
    duration confound is two orders of magnitude larger than the count ones,
    and a log scale detaches the bars from a meaningful zero.
    """
    panels = [
        ("Event-count features", ["graph__n_proc_events", "temporal__n_events"],
         ["Process events\nper incident", "Total events\nper incident"], 1.35),
        ("Incident duration", ["temporal__duration_s"], ["Duration"], 260),
    ]
    data = {}
    for ver, path in [("v0.2.0 (before fix)", "reports/features_v2.csv"),
                      ("v0.3.0 (after fix)", "reports/features_v3.csv")]:
        df = pd.read_csv(path)
        m = df.groupby("label").mean(numeric_only=True)
        data[ver] = {f: m.loc["malicious", f] / m.loc["benign", f]
                     for _, feats, _, _ in panels for f in feats}

    fig, axes = plt.subplots(1, 2, figsize=(10.4, 3.2),
                             gridspec_kw={"width_ratios": [2, 1]})
    for ax, (title, feats, nice, xmax) in zip(axes, panels):
        y = range(len(feats))
        h = 0.34
        b1 = ax.barh([i + h / 2 for i in y], [data["v0.2.0 (before fix)"][f] for f in feats],
                     height=h, color=S2, label="v0.2.0 (before fix)", zorder=3)
        b2 = ax.barh([i - h / 2 for i in y], [data["v0.3.0 (after fix)"][f] for f in feats],
                     height=h, color=S1, label="v0.3.0 (after fix)", zorder=3)
        _labels(ax, b1, fmt="{:.1f}\u00d7", pad=xmax * 0.02)
        _labels(ax, b2, fmt="{:.1f}\u00d7", pad=xmax * 0.02)
        ax.axvline(1.0, color=INK2, linewidth=1.2, linestyle=(0, (4, 3)), zorder=4)
        ax.set_yticks(list(y)); ax.set_yticklabels(nice)
        ax.set_title(title, loc="left", color=INK, fontsize=11)
        _style(ax, xlabel="malicious \u00f7 benign", xlim=(0, xmax))
    axes[1].text(3, 0.42, "parity (1.0\u00d7)", fontsize=8.5, color=INK2, va="bottom")
    h_, l_ = axes[0].get_legend_handles_labels()
    fig.legend(h_, l_, frameon=False, fontsize=9, ncol=2,
               loc="upper right", bbox_to_anchor=(0.995, 1.015))
    fig.suptitle("Generator confounds: class-mean ratio of each leaked feature",
                 x=0.012, ha="left", fontsize=13, fontweight="600", color=INK)
    fig.text(0.012, -0.08,
             "Duration leaked at 211\u00d7 before the fix \u2014 dwell-time scaling had been applied only to attacks. "
             "Both confounds now sit near parity.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(OUT / "02_generator_confounds.png", bbox_inches="tight")
    plt.close(fig)
    print("02_generator_confounds.png")


def fig_rules_tradeoff(log: pd.DataFrame) -> None:
    """What the proposal's §8 weights actually buy, across dataset difficulty."""
    d = log[(log["model"] == "rules") & (log["split_policy"] == "time")]
    d = d.drop_duplicates(subset=["data_version"], keep="last").sort_values("data_version")
    vers = [f"v{v}" for v in d["data_version"].astype(str)]
    y = range(len(vers))
    h = 0.26
    fig, ax = plt.subplots(figsize=(8.6, 2.9))
    for off, col, key, lab in [(h, S1, "precision", "Precision"),
                               (0, S2, "recall", "Recall"),
                               (-h, S3, "fpr", "False-positive rate")]:
        bars = ax.barh([i + off for i in y], d[key].to_numpy(), height=h,
                       color=col, label=lab, zorder=3)
        _labels(ax, bars)
    ax.set_yticks(list(y))
    ax.set_yticklabels([f"{v}\n{'no evasion' if v=='v0.1.0' else 'full evasion'}" for v in vers])
    ax.legend(frameon=False, fontsize=9, ncol=3, loc="lower center",
              bbox_to_anchor=(0.5, -0.42))
    ax.set_title("Proposal §8 risk weights: perfect precision, 61% of attacks missed",
                 loc="left", color=INK)
    _style(ax, xlim=(0, 1.18))
    fig.text(0.012, -0.22,
             "Weights implemented verbatim from proposal §8, thresholded at the High band (≥60). "
             "Evasion variants cost a further 7 points of recall. FPR is 0.000 at every version.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.savefig(OUT / "03_rules_only_tradeoff.png", bbox_inches="tight")
    plt.close(fig)
    print("03_rules_only_tradeoff.png")


def fig_importance() -> None:
    """Top non-rule features the RF relies on. Single series -> no legend."""
    from sklearn.ensemble import RandomForestClassifier
    from analysis.features import all_groups, columns_for
    from ml.baseline import make_split

    df = pd.read_csv("reports/features_v3.csv").reset_index(drop=True)
    cols = columns_for(df, [g for g in all_groups(df) if g != "rules"])
    tr, _ = make_split(df, "time", 7)
    m = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                               class_weight="balanced_subsample", random_state=7, n_jobs=-1)
    m.fit(df.loc[tr, cols], df.loc[tr, "y"])
    imp = pd.Series(m.feature_importances_, index=cols).sort_values(ascending=False).head(12)[::-1]

    fig, ax = plt.subplots(figsize=(8.6, 4.4))
    bars = ax.barh(range(len(imp)), imp.to_numpy(), color=S1, height=0.62, zorder=3)
    _labels(ax, bars, fmt="{:.3f}", pad=0.001)
    ax.set_yticks(range(len(imp)))
    ax.set_yticklabels([i.replace("__", " · ") for i in imp.index], fontsize=9)
    ax.set_title("Which non-rule evidence the model leans on (v0.3.0, chronological split)",
                 loc="left", color=INK)
    _style(ax, xlabel="Gini importance", xlim=(0, max(imp) * 1.18))
    fig.text(0.012, -0.03,
             "Interpret with care: importance ranks what separates THIS synthetic corpus, "
             "not what matters on real telemetry.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.savefig(OUT / "04_feature_importance.png", bbox_inches="tight")
    plt.close(fig)
    print("04_feature_importance.png")


def fig_composition() -> None:
    """Dataset makeup: incidents per scenario family, coloured by ground truth."""
    df = pd.read_csv("reports/features_v3.csv")
    g = (df.groupby(["scenario_family", "label"]).size()
         .reset_index(name="n").sort_values(["label", "n"]))
    colors = {"malicious": S2, "suspicious": S3, "benign": S1}
    g["hard"] = g["scenario_family"].map(
        df.groupby("scenario_family")["is_hard_negative"].max())

    fig, ax = plt.subplots(figsize=(8.6, 5.0))
    for i, (_, r) in enumerate(g.iterrows()):
        bar = ax.barh(i, r["n"], color=colors[r["label"]], height=0.66, zorder=3)
        ax.text(r["n"] + 1.5, i, f"{int(r['n'])}" + ("  hard negative" if r["hard"] else ""),
                va="center", fontsize=8.5, color=INK2)
    ax.set_yticks(range(len(g)))
    ax.set_yticklabels(g["scenario_family"], fontsize=9)
    handles = [plt.Rectangle((0, 0), 1, 1, color=colors[k]) for k in ["benign", "suspicious", "malicious"]]
    ax.legend(handles, ["benign", "suspicious", "malicious"], frameon=False,
              loc="lower right", fontsize=9)
    ax.set_title("Synthetic corpus v0.3.0: 800 incidents across 14 scenario families",
                 loc="left", color=INK)
    _style(ax, xlabel="incidents", xlim=(0, g["n"].max() * 1.35))
    fig.text(0.012, -0.025,
             "Six benign families are hard negatives — benign activity that fires attack rules. "
             "55.9% of benign incidents trip at least one rule.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.savefig(OUT / "05_dataset_composition.png", bbox_inches="tight")
    plt.close(fig)
    print("05_dataset_composition.png")


def fig_intel_signal() -> None:
    """Real abuse.ch intel: clean on file hashes, noisy on domains.

    Reads the feature table produced with --intel (make features-intel). The two
    panels are the whole finding: known-bad hashes never touch benign traffic,
    while known-bad domains flag benign incidents whose legitimate infrastructure
    (github.com) is itself abused and therefore listed by URLhaus.
    """
    df = pd.read_csv("reports/features_intel.csv")
    labels = ["benign", "suspicious", "malicious"]
    colors = {"benign": S1, "suspicious": S3, "malicious": S2}
    panels = [("Known-bad file hash", "intel__n_known_bad_hashes"),
              ("Known-bad domain", "intel__n_known_bad_domains")]

    fig, axes = plt.subplots(1, 2, figsize=(10.4, 3.6), sharey=True)
    for ax, (title, col) in zip(axes, panels):
        counts = [int(((df["label"] == l) & (df[col] > 0)).sum()) for l in labels]
        bars = ax.bar(range(len(labels)), counts, width=0.6,
                      color=[colors[l] for l in labels], zorder=3)
        for b, c in zip(bars, counts):
            ax.text(b.get_x() + b.get_width() / 2, c + max(counts + [1]) * 0.02, str(c),
                    ha="center", va="bottom", fontsize=9, color=INK2)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels)
        ax.set_title(title, loc="left", color=INK, fontsize=11)
        ax.set_ylim(0, max(counts + [1]) * 1.22)
        ax.grid(axis="y", alpha=0.7)
        ax.set_axisbelow(True)
        ax.tick_params(length=0)
    axes[0].set_ylabel("incidents matching", color=INK2)
    fig.suptitle("Real threat intel separates malware on hashes, not on domains",
                 x=0.012, ha="left", fontsize=13, fontweight="600", color=INK)
    fig.text(0.012, -0.05,
             "abuse.ch index: 11,246 domains \u00b7 781 IPs \u00b7 3,168 hashes. Known-bad hashes never hit benign "
             "traffic; known-bad domains flag benign incidents \u2014 all github.com \u2014 because legitimate "
             "infrastructure is abused.",
             fontsize=8.5, color=MUTED, ha="left")
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    fig.savefig(OUT / "06_intel_signal.png", bbox_inches="tight")
    plt.close(fig)
    print("06_intel_signal.png")


def _skip_if_missing(name: str, fn, inputs: list[str]) -> None:
    """Run a figure only when all its inputs exist.

    Some figures depend on historical feature tables that the current generator
    can no longer reproduce (e.g. features_v2.csv predates the confound fix), so
    a missing input is expected, not an error.
    """
    missing = [p for p in inputs if not Path(p).exists()]
    if missing:
        print(f"skip {name}: missing {', '.join(missing)}")
        return
    fn()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    log = pd.read_csv("reports/experiments.csv")
    fig_ablation(log)
    fig_rules_tradeoff(log)
    _skip_if_missing("02_generator_confounds.png", fig_confound,
                     ["reports/features_v2.csv", "reports/features_v3.csv"])
    _skip_if_missing("04_feature_importance.png", fig_importance, ["reports/features_v3.csv"])
    _skip_if_missing("05_dataset_composition.png", fig_composition, ["reports/features_v3.csv"])
    _skip_if_missing("06_intel_signal.png", fig_intel_signal, ["reports/features_intel.csv"])
    print(f"\nfigures written to {OUT}/")


if __name__ == "__main__":
    main()
