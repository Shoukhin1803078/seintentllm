"""Incident-level feature extraction for SentinelLLM (Person 2).

One row per incident. Features are organised into GROUPS so the ablation can
train with and without the rule-derived features:

    rules          binary rule-hit indicators (what Person 1's engine already knows)
    static         signature, path, prevalence, naming-entropy evidence
    temporal       chain duration, inter-event cadence, exec->network latency
    graph          process-tree shape
    network        domain rarity, egress volume, reputation
    corroboration  independent AV/YARA/sandbox verdicts
    visual         screenshot presence and deceptive-text cues
    intel          matches against a real abuse.ch reputation index (opt-in)

The `intel` group is only emitted when a reputation index is supplied with
--intel (see intel/build_index.py). Without it the output is byte-identical to
the pre-intel pipeline, so existing experiments still reproduce.

Why this matters: if the model is trained only on `rules`, then "ML only" and
"Rules only" in the ablation (proposal section 11) measure the same thing and the
comparison is vacuous. The non-rule groups are where a learned model can add
information the deterministic engine does not have.

Usage
    python analysis/features.py --data data_synthetic/v1 --out reports/features.csv
    python analysis/features.py --data data_synthetic/v4 --intel data_real/intel/v1/reputation.json
"""
from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path

import pandas as pd

RULE_IDS = [f"R{i:03d}" for i in range(1, 13)]

FEATURE_GROUPS: dict[str, list[str]] = {}


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def extract(events: list[dict], incident: dict, intel: dict | None = None) -> dict:
    """All features for one incident. Keys are prefixed with their group name."""
    f: dict[str, float] = {}
    times = sorted(_ts(e["timestamp"]) for e in events)
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])] or [0.0]

    # --- rules ---------------------------------------------------------------
    hits = set(incident.get("rule_hits", []))
    for r in RULE_IDS:
        f[f"rules__{r}"] = int(r in hits)
    f["rules__n_distinct"] = len(hits)

    # --- static --------------------------------------------------------------
    procs = [e["process"] for e in events if "process" in e]
    files = [e["file"] for e in events if "file" in e]
    f["static__n_unsigned_proc"] = sum(1 for p in procs if not p.get("signed"))
    f["static__frac_unsigned_proc"] = (f["static__n_unsigned_proc"] / len(procs)) if procs else 0.0
    f["static__n_untrusted_signer_proc"] = sum(1 for p in procs if not p.get("signer_trusted"))
    f["static__n_temp_proc"] = sum(1 for p in procs if p.get("path_category") == "user_temp")
    f["static__n_unsigned_temp_proc"] = sum(
        1 for p in procs if p.get("path_category") == "user_temp" and not p.get("signed"))
    f["static__n_new_files"] = sum(1 for x in files if x.get("first_seen_hours") is None)
    f["static__n_unknown_prevalence"] = sum(1 for x in files if x.get("prevalence") == "unknown")
    f["static__n_encrypted_archive"] = sum(1 for x in files if x.get("archive_encrypted"))
    ents = [x.get("name_entropy", 0.0) for x in files]
    f["static__max_name_entropy"] = max(ents) if ents else 0.0
    f["static__mean_name_entropy"] = statistics.fmean(ents) if ents else 0.0
    f["static__max_cmdline_len"] = max((p.get("cmdline_len", 0) for p in procs), default=0)
    f["static__n_credential_access"] = sum(1 for e in events if "credential_target" in e)
    f["static__n_distinct_cred_stores"] = len(
        {e["credential_target"]["store"] for e in events if "credential_target" in e})
    f["static__n_persistence_writes"] = sum(
        1 for e in events if e["event_type"] in {"registry_set", "scheduled_task_create",
                                                 "service_create", "wmi_subscription"})

    # --- temporal ------------------------------------------------------------
    f["temporal__duration_s"] = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0.0
    f["temporal__n_events"] = len(events)
    f["temporal__median_gap_s"] = statistics.median(gaps)
    f["temporal__min_gap_s"] = min(gaps)
    f["temporal__gap_stdev_s"] = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    f["temporal__events_per_min"] = len(events) / max(f["temporal__duration_s"] / 60.0, 1e-6)
    f["temporal__burstiness"] = (f["temporal__gap_stdev_s"] / statistics.fmean(gaps)) if statistics.fmean(gaps) else 0.0
    # Latency from first unsigned/Temp execution to the next outbound connection:
    # fast exec->egress is a staging signature no single rule captures.
    exec_t = [_ts(e["timestamp"]) for e in events
              if e["event_type"] == "process_create" and not e.get("process", {}).get("signer_trusted", True)]
    net_t = [_ts(e["timestamp"]) for e in events if e["event_type"] == "network_connect"]
    lat = [(n - x).total_seconds() for x in exec_t for n in net_t if n >= x]
    f["temporal__exec_to_egress_s"] = min(lat) if lat else -1.0
    f["temporal__has_exec_then_egress"] = int(bool(lat))

    # --- graph ---------------------------------------------------------------
    depths = [p.get("tree_depth", 0) for p in procs]
    f["graph__max_tree_depth"] = max(depths) if depths else 0
    f["graph__mean_tree_depth"] = statistics.fmean(depths) if depths else 0.0
    f["graph__n_distinct_proc_names"] = len({p.get("name") for p in procs})
    f["graph__n_proc_events"] = len(procs)
    f["graph__proc_name_reuse"] = (len(procs) / f["graph__n_distinct_proc_names"]) if procs else 0.0

    # --- network -------------------------------------------------------------
    nets = [e["network"] for e in events if "network" in e]
    rar = [n.get("domain_rarity", 0.0) for n in nets]
    f["network__n_connections"] = len(nets)
    f["network__max_domain_rarity"] = max(rar) if rar else 0.0
    f["network__mean_domain_rarity"] = statistics.fmean(rar) if rar else 0.0
    f["network__n_rare_domains"] = sum(1 for r in rar if r > 0.7)
    f["network__n_distinct_domains"] = len({n.get("domain") for n in nets})
    f["network__total_bytes_out"] = sum(n.get("bytes_out", 0) for n in nets)
    f["network__max_bytes_out"] = max((n.get("bytes_out", 0) for n in nets), default=0)
    f["network__n_bad_reputation"] = sum(1 for n in nets if n.get("reputation") in {"suspicious", "malicious"})
    ages = [n.get("domain_age_days") for n in nets if n.get("domain_age_days") is not None]
    f["network__min_domain_age_days"] = min(ages) if ages else -1.0

    # --- corroboration -------------------------------------------------------
    dets = [e["detection"] for e in events if "detection" in e]
    f["corroboration__n_detections"] = len(dets)
    f["corroboration__any_malicious_verdict"] = int(any(d.get("verdict") == "malicious" for d in dets))
    f["corroboration__max_confidence"] = max((d.get("confidence", 0.0) for d in dets), default=0.0)
    f["corroboration__n_distinct_sources"] = len({d.get("source") for d in dets})

    # --- visual --------------------------------------------------------------
    vis = [e["visual"] for e in events if "visual" in e]
    f["visual__n_screenshots"] = len(vis)
    # Keyword cues stand in for the VLM until the real detector exists (week 8).
    # NOTE: page_text_excerpt is attacker-controlled. Used here only as bag-of-words
    # features, never injected into an LLM prompt. See docs/threat_model_ai.md.
    cues = ("windows+r", "run dialog", "press win", "paste", "verification command",
            "not a robot", "checkpoint failed")
    txt = " ".join(v.get("page_text_excerpt", "").lower() for v in vis)
    f["visual__deceptive_text_cues"] = sum(1 for c in cues if c in txt)
    f["visual__has_clipboard_write"] = int(any(e["event_type"] == "clipboard_write" for e in events))
    f["visual__screenshot_then_exec"] = int(
        bool(vis) and any(e["event_type"] == "process_create" for e in events))

    # --- intel (opt-in) ------------------------------------------------------
    # Real reputation lookups against an abuse.ch index. Only the raw attributes
    # abuse.ch exposes are used (family, threat type, confidence) - deliberately
    # NOT a bare "is on a blocklist" bit, which would just leak the label.
    if intel is not None:
        dom_index = intel.get("domains", {})
        hash_index = intel.get("hashes", {})
        bad_domains = sorted({n["domain"] for n in nets
                              if n.get("domain") and n["domain"] in dom_index})
        bad_hashes = sorted({x["sha256"] for x in files
                             if x.get("sha256") and x["sha256"] in hash_index})
        families = {dom_index[d].get("family") for d in bad_domains}
        families |= {hash_index[h].get("family") for h in bad_hashes}
        confs = [dom_index[d].get("confidence") for d in bad_domains
                 if dom_index[d].get("confidence") is not None]
        f["intel__n_known_bad_domains"] = len(bad_domains)
        f["intel__n_known_bad_hashes"] = len(bad_hashes)
        f["intel__n_families"] = len({x for x in families if x})
        f["intel__max_confidence"] = max(confs) if confs else 0
        f["intel__any_match"] = int(bool(bad_domains or bad_hashes))

    return f


def build(data_dir: Path, intel: dict | None = None) -> pd.DataFrame:
    events = _load_jsonl(data_dir / "events.jsonl")
    incidents = _load_jsonl(data_dir / "incidents.jsonl")
    by_inc: dict[str, list[dict]] = {}
    for e in events:
        by_inc.setdefault(e["incident_id"], []).append(e)

    rows = []
    for inc in incidents:
        row = {"incident_id": inc["incident_id"]}
        row.update(extract(by_inc[inc["incident_id"]], inc, intel))
        row["label"] = inc["label"]
        row["y"] = int(inc["label"] == "malicious")
        row["scenario_family"] = inc["scenario_family"]
        row["scenario_variant"] = inc["scenario_variant"]
        row["is_hard_negative"] = int(inc["is_hard_negative"])
        row["n_true_stages"] = len(inc.get("ground_truth_stages", []))
        row["start_time"] = inc["start_time"]
        rows.append(row)
    return pd.DataFrame(rows)


def group_of(col: str) -> str | None:
    return col.split("__")[0] if "__" in col else None


def columns_for(df: pd.DataFrame, groups: list[str]) -> list[str]:
    return [c for c in df.columns if group_of(c) in set(groups)]


def all_groups(df: pd.DataFrame) -> list[str]:
    return sorted({g for c in df.columns if (g := group_of(c))})


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=Path("data_synthetic/v1"))
    p.add_argument("--out", type=Path, default=Path("reports/features.csv"))
    p.add_argument("--intel", type=Path, default=None,
                   help="abuse.ch reputation index (intel/build_index.py). Adds the "
                        "`intel` feature group; omit for the pre-intel feature set.")
    a = p.parse_args()
    intel = json.loads(a.intel.read_text()) if a.intel else None
    df = build(a.data, intel)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)

    # Auto-generate the feature dictionary the guide asks for (features.md).
    lines = ["# Feature dictionary", "",
             f"Generated from `{a.data}` - {len(df)} incidents, "
             f"{len(columns_for(df, all_groups(df)))} features.", ""]
    for g in all_groups(df):
        cols = columns_for(df, [g])
        lines.append(f"## {g} ({len(cols)} features)")
        lines += [f"- `{c}`" for c in cols] + [""]
    Path("docs/features.md").write_text("\n".join(lines))

    print(f"wrote {a.out}  shape={df.shape}")
    print("groups:", {g: len(columns_for(df, [g])) for g in all_groups(df)})
    print(df.groupby("label")["incident_id"].count().to_string())


if __name__ == "__main__":
    main()
