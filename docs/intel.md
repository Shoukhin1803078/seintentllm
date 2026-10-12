# abuse.ch threat-intel integration

**Status:** implemented (v0.4.0 generator). See `intel/README.md` for usage.

This document records *why* abuse.ch is wired into the pipeline the way it is,
and what it can and cannot evidence. It is the design rationale; the operational
how-to lives in `intel/README.md`.

## Why

The pipeline was built entirely on synthetic data because Person 1's collector
does not exist yet (`docs/schema.md`). The synthetic generator invents its C2
domains (`rare_domain`) and payload hashes (`rand_hex`). That is fine for
exercising the pipeline, but it means the `network` and `static` features are
measured against fictional infrastructure.

abuse.ch supplies **real, current malicious indicators**. Grounding the
generator's indicator values in them makes the network/file reputation features
reflect real threat intel, without pretending to have real host telemetry.

## What was chosen

A **reputation-enrichment layer** (`intel/`):

- `intel/abusech.py` — metadata-only client for MalwareBazaar, ThreatFox,
  URLhaus. Auth via `ABUSECH_AUTH_KEY` or `.abusech_key`; disk cache; 1 req/s.
- `intel/build_index.py` — normalises the feeds into `domains` / `ips` /
  `hashes` lookup tables plus a provenance manifest, under the gitignored
  `data_real/`.
- `data_synthetic/generate.py --intel` — for malicious incidents, replaces
  synthetic C2/exfil domains and payload hashes with real ones. Domains already
  on reputable hosting (`LEGIT_HOSTING`) are kept, preserving the "C2 on
  reputable infrastructure" evasion. Benign incidents are untouched.
- `analysis/features.py --intel` — adds an opt-in `intel` feature group
  (`n_known_bad_domains`, `n_known_bad_hashes`, `n_families`, `max_confidence`,
  `any_match`).

The default pipeline is unchanged: without `--intel`, feature output is
byte-identical to the pre-intel pipeline (58 features, 7 groups).

## Mapping into the schema

| abuse.ch field | Schema field |
|---|---|
| ThreatFox `ioc` / URLhaus `url` host | `network.domain` |
| MalwareBazaar `sha256_hash` | `file.sha256` |
| MalwareBazaar `signature` | malware family |
| MalwareBazaar `code_sign.subject_cn` / `cscb_listed` | file signer / `signer_trusted` context |
| MalwareBazaar `intelligence.clamav` | `detection` block context |
| ThreatFox `confidence_level` | `intel__max_confidence` |
| `provenance.source` | stays `synthetic`; `intel_version` added |

`incidents.v1.json` `provenance` gained an optional `intel_version` field for
this. `provenance.source` remains `synthetic`: the events are still generated —
only the indicator values are real.

## Observed on live data (2026-10-12)

Built from all three feeds — 1,000 MalwareBazaar + 8,987 ThreatFox + 32,834
URLhaus entries → **11,246 domains, 781 IPs, 3,168 hashes** — then grounded a
full v4 dataset (113 C2/exfil domains and 266 payload hashes replaced with real
ones). Two results, one useful and one cautionary.

**File-hash intel is clean.** 266 real malware hashes landed on malicious
incidents; **zero** benign or suspicious incidents matched a known-bad hash.
Known-bad hashes are a strong, low-FP signal.

**Domain intel is not.** 414 benign incidents matched the index — every one of
them on `github.com`. `cdn.discordapp.com`, `drive.google.com` and
`raw.githubusercontent.com` (the generator's benign "reputable hosting" set)
are in URLhaus too.

Legitimate, ubiquitous infrastructure appears in real threat intel because it is
abused. So "domain ∈ blocklist" is a **false-positive generator**, not a clean
signal — precisely the reputable-hosting / allowlist-suppression failure the
project already warns about (`docs/threat_model_ai.md`, T3). Two consequences:

1. The `intel` group uses raw abuse.ch attributes (family, threat type,
   confidence) rather than a bare membership bit, but its `any_match` /
   `n_known_bad_domains` columns inherit this weakness. Treat intel features as
   *informative but FP-prone*, and expect them to hurt precision until filtered.
2. URLhaus itself excludes Tranco Top-1M domains from its RPZ/hostfile feeds for
   exactly this reason (the full CSV dump does not). A future refinement is to
   apply a popularity filter to the index, or to weight by ThreatFox confidence.

This is a measurement, not a defect in the wiring: it is the same class of
finding as `reports/findings_week1.md`, and it argues for the same thing — real
benign telemetry is needed to quantify it.

## Limits (stated up front)

1. **No benign class.** abuse.ch accepts confirmed malware only and PUPs are
   rejected. The false-positive rate — the metric the proposal commits to — is
   still unmeasurable from synthetic + abuse.ch data. Real benign capture remains
   a hard prerequisite (`STATUS.md` §3).
2. **No host telemetry.** abuse.ch is file/IOC-centric: no process trees,
   registry, credential access or incident correlation. It cannot replace the
   generator, only ground it.
3. **Separability is not fixed.** Grounding indicators in real IOCs does not
   change the synthetic-by-construction separability documented in
   `reports/findings_week1.md`. RF F1 will still be near-perfect on a time split;
   the leave-families-out number remains the honest one.
4. **Timeliness.** ThreatFox IOCs expire after 6 months; an index is a snapshot.
   Regenerate it (`make intel`) rather than committing it.

## Compliance

abuse.ch community APIs are free under fair use; commercial use needs the paid
enhanced API. Never commit the Auth-Key (`.abusech_key` is gitignored), never
commit fetched intel (`data_real/` is gitignored), and never download or store
malware samples.
