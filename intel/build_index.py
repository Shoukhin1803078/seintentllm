"""Build a SentinelLLM reputation index from abuse.ch feeds.

Normalises MalwareBazaar, ThreatFox and URLhaus metadata into three lookup
tables that the rest of the pipeline can join against:

    domains[domain] -> {source, family, threat_type, confidence, first_seen, tags}
    ips[ip]         -> {source, family, threat_type, confidence, first_seen, tags}
    hashes[sha256]  -> {source, family, tags, clamav, signer, issuer_cn,
                        cscb_listed, file_type, first_seen}

The result is written under data_real/ (gitignored) together with a small
manifest that records provenance - source counts, fetch time and a
non-reversible fingerprint of the Auth-Key that produced it.

Usage
    python intel/build_index.py --out data_real/intel/v1
    python intel/build_index.py --out data_real/intel/v1 --offline --fixtures intel/fixtures
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from intel import abusech  # noqa: E402

INDEX_VERSION = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rec(source: str, *, family=None, threat_type=None, confidence=None,
         first_seen=None, tags=None) -> dict:
    return {
        "source": source,
        "family": family or None,
        "threat_type": threat_type or None,
        "confidence": confidence,
        "first_seen": first_seen,
        "tags": tags or [],
    }


def _hash_rec(source: str, *, family=None, threat_type=None, confidence=None,
              first_seen=None, tags=None, clamav=None, signer=None,
              issuer_cn=None, cscb_listed=False, file_type=None) -> dict:
    """One shape for every hash record, whichever feed it came from, so the join
    in analysis/features.py never has to branch on source."""
    return _rec(source, family=family, threat_type=threat_type, confidence=confidence,
                first_seen=first_seen, tags=tags) | {
        "clamav": clamav, "signer": signer, "issuer_cn": issuer_cn,
        "cscb_listed": bool(cscb_listed), "file_type": file_type,
    }


def normalize_threatfox(iocs: list[dict], domains: dict, ips: dict, hashes: dict) -> None:
    for ioc in iocs:
        value = ioc.get("ioc")
        if not value:
            continue
        family = ioc.get("malware_printable") or ioc.get("malware")
        rec = _rec("threatfox", family=family, threat_type=ioc.get("threat_type"),
                   confidence=ioc.get("confidence_level"),
                   first_seen=ioc.get("first_seen"), tags=ioc.get("tags"))
        kind = ioc.get("ioc_type")
        if kind == "domain":
            domains[value.lower()] = rec
        elif kind == "ip:port":
            ips[value.split(":")[0]] = rec
        elif kind == "url":
            host = urlsplit(value).hostname
            if host:
                domains[host.lower()] = rec
        elif kind == "sha256_hash":
            hashes[value.lower()] = _hash_rec(
                "threatfox", family=family, threat_type=ioc.get("threat_type"),
                confidence=ioc.get("confidence_level"),
                first_seen=ioc.get("first_seen"), tags=ioc.get("tags"))


def _code_sign(sample: dict) -> tuple[str | None, str | None]:
    signers = sample.get("code_sign")
    if isinstance(signers, list) and signers and isinstance(signers[0], dict):
        return signers[0].get("subject_cn"), signers[0].get("issuer_cn")
    return None, None


def normalize_malwarebazaar(samples: list[dict], hashes: dict) -> None:
    for s in samples:
        sha = s.get("sha256_hash")
        if not sha:
            continue
        subject, issuer = _code_sign(s)
        intel = s.get("intelligence") or {}
        hashes[sha.lower()] = _hash_rec(
            "malwarebazaar", family=s.get("signature"), threat_type="malware_sample",
            first_seen=s.get("first_seen"), tags=s.get("tags"),
            clamav=intel.get("clamav"), signer=subject, issuer_cn=issuer,
            cscb_listed=s.get("cscb_listed"), file_type=s.get("file_type"))


def normalize_urlhaus(csv_text: str, domains: dict) -> int:
    """Parse a URLhaus CSV dump. The public dump comments every line, including
    the real header ("# id,dateadded,url,..."), so detect the header row by its
    fields, drop comments, and count URL rows. Returns the number processed."""
    lines = [l for l in csv_text.splitlines() if l.strip()]
    header_i = None
    for i, line in enumerate(lines):
        fields = next(csv.reader([line.lstrip("# ")]), [])
        if [f.strip() for f in fields][:2] == ["id", "dateadded"]:
            header_i = i
            break
    if header_i is None:
        return 0
    body = []
    for line in lines[header_i:]:
        line = line[2:] if line.startswith("# ") else line
        if not line.lstrip().startswith("#"):
            body.append(line)
    n = 0
    for row in csv.DictReader(body):
        url = (row.get("url") or "").strip()
        host = urlsplit(url).hostname
        if not host:
            continue
        domains.setdefault(host.lower(), _rec(
            "urlhaus", threat_type=row.get("threat"), first_seen=row.get("dateadded"),
            tags=[t for t in (row.get("tags") or "").split(",") if t]))
        n += 1
    return n


def build(threatfox: list[dict], mb_samples: list[dict], urlhaus_csv: str,
          auth_key_id: str | None, days: int, offline: bool) -> dict:
    domains: dict = {}
    ips: dict = {}
    hashes: dict = {}
    normalize_threatfox(threatfox, domains, ips, hashes)
    normalize_malwarebazaar(mb_samples, hashes)
    n_urlhaus = normalize_urlhaus(urlhaus_csv, domains)
    return {
        "index_version": INDEX_VERSION,
        "generated_at": _now(),
        "auth_key_id": auth_key_id,
        "offline": offline,
        "source_counts": {
            "malwarebazaar": len(mb_samples),
            "threatfox": len(threatfox),
            "urlhaus": n_urlhaus,
        },
        "counts": {"domains": len(domains), "ips": len(ips), "hashes": len(hashes)},
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
    }


def _load_fixtures(fixtures: Path) -> tuple[list[dict], list[dict], str]:
    mb = json.loads((fixtures / "malwarebazaar_recent.json").read_text())
    tf = json.loads((fixtures / "threatfox_iocs.json").read_text())
    uh = (fixtures / "urlhaus_recent.csv").read_text()
    return tf, mb, uh


def main() -> None:
    p = argparse.ArgumentParser(description="Build a SentinelLLM reputation index from abuse.ch.")
    p.add_argument("--out", type=Path, default=Path("data_real/intel/v1"))
    p.add_argument("--days", type=int, default=7, help="ThreatFox lookback (1-7).")
    p.add_argument("--mb-filetypes", default="exe,dll,js,ps1,jar,elf,doc,rtf,zip",
                   help="Comma-separated file types to pull recent MalwareBazaar samples for.")
    p.add_argument("--mb-limit", type=int, default=200,
                   help="Max MalwareBazaar samples per file type (1-1000).")
    p.add_argument("--offline", action="store_true", help="Use committed fixtures, no network.")
    p.add_argument("--fixtures", type=Path, default=Path("intel/fixtures"))
    a = p.parse_args()

    if a.offline:
        tf, mb, uh = _load_fixtures(a.fixtures)
        key_id = None
    else:
        key_id = abusech.auth_key_id() if abusech.has_key() else None
        uh = abusech.urlhaus_recent_csv()
        if abusech.has_key():
            tf = abusech.threatfox_iocs(a.days)
            mb = list(abusech.malwarebazaar_recent("100"))
            for ft in [x.strip() for x in a.mb_filetypes.split(",") if x.strip()]:
                mb += abusech.malwarebazaar_filetype(ft, a.mb_limit)
        else:
            print("warning: no abuse.ch Auth-Key - building from public URLhaus only. "
                  "Set ABUSECH_AUTH_KEY to add MalwareBazaar + ThreatFox.", file=sys.stderr)
            tf, mb = [], []

    index = build(tf, mb, uh, key_id, a.days, a.offline)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "reputation.json").write_text(json.dumps(index, indent=2) + "\n")

    manifest = {k: index[k] for k in
                ("index_version", "generated_at", "auth_key_id", "offline",
                 "source_counts", "counts")}
    manifest["days"] = a.days
    (a.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
