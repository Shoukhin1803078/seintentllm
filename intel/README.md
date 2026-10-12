# abuse.ch reputation layer (`intel/`)

Pulls **metadata only** from three [abuse.ch](https://abuse.ch/) community feeds
and turns it into a reputation index the pipeline can join against, so that the
network / file / intel features rest on real threat intel instead of invented
indicators.

| Feed | Endpoint | Contributes |
|---|---|---|
| MalwareBazaar | `POST https://mb-api.abuse.ch/api/v1/` | file hashes, family, ClamAV, code-signing cert + CSCB status |
| ThreatFox | `POST https://threatfox-api.abuse.ch/api/v1/` | C2 domains, IPs, URLs → malware family, confidence |
| URLhaus | `GET https://urlhaus-api.abuse.ch/v2/files/exports/<KEY>/recent.csv` | malware-distribution URLs → hosts, payload tags |

Feodo Tracker is intentionally excluded (its dataset has been empty since
Operation Endgame). YARAify is a possible future source for the `detection`
block. **No malware samples are ever downloaded** — only the JSON/CSV metadata.

## Setup

```bash
# free key: https://auth.abuse.ch/
export ABUSECH_AUTH_KEY=...        # or write it to .abusech_key (gitignored)
```

The key is needed for **MalwareBazaar** and **ThreatFox**. **URLhaus works
without one** — the client falls back to its public CSV dump, so `make intel`
already produces a real (URLhaus-only) index with no key. Setting the key adds
file hashes, families and C2 indicators on top.

## Usage

```bash
# 1. build the reputation index (writes to the gitignored data_real/)
make intel                       # live feeds
make intel-offline               # committed fixtures, no key / no network

# 2. generate a dataset grounded in real indicators, then feature it
make data-intel                  # -> data_synthetic/v4
make features-intel              # -> reports/features_intel.csv (adds `intel` group)

# or drive the scripts directly
python intel/build_index.py --out data_real/intel/v1
python data_synthetic/generate.py --out data_synthetic/v4 \
    --intel data_real/intel/v1/reputation.json
python analysis/features.py --data data_synthetic/v4 \
    --intel data_real/intel/v1/reputation.json --out reports/features_intel.csv

# smoke test connectivity
python intel/abusech.py --smoke
```

## Index format

`data_real/intel/v1/reputation.json` — three lookup tables (`domains`, `ips`,
`hashes`) plus provenance. Every record carries `source`, `family`,
`threat_type`, `confidence`, `first_seen`, `tags`; `hashes` records add
`clamav`, `signer`, `issuer_cn`, `cscb_listed`, `file_type`. A companion
`manifest.json` records source counts and a non-reversible fingerprint of the
Auth-Key (`auth_key_id`), never the key itself.

## What this does and does not do

**Does:** ground malicious C2/exfil domains and payload hashes in real
indicators (`generate.py --intel`), and expose real reputation as an opt-in
`intel` feature group (`features.py --intel`). The default pipeline is unchanged
— without `--intel` the output is byte-identical to before, so existing
experiments still reproduce.

**Does not:** make the incidents real, or provide negatives. abuse.ch contains
**confirmed malware only** (PUPs are rejected) and no host telemetry, so it
cannot supply a benign class. The false-positive rate — the headline concern in
`reports/findings_week1.md` — still requires a real benign capture from Person 1.
Treat the `intel` features as real, and everything else as still synthetic.

**Leakage caution:** a bare "is in a blocklist" bit would leak the label. The
generator only replaces indicator *values*; feature extraction uses the raw
abuse.ch attributes (family, threat type, confidence), never a membership flag.
The leave-families-out split remains the honest generalisation test.

## Terms

Community APIs are free under the abuse.ch
[fair-use principles](https://abuse.ch/terms-of-use/#principles). Commercial use
requires the paid enhanced API. The client throttles to 1 request/second and
caches raw responses under `data_real/intel/cache/`.
