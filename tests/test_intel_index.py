"""Tests for the abuse.ch reputation layer.

Covers three things the guide's conformance suite cares about:
  1. the reputation index has the shape the join expects;
  2. the index can be built offline from committed fixtures (no key, no network);
  3. an intel-grounded dataset still satisfies the event/incident schemas and
     only malicious incidents actually match real indicators.

Run directly (like tests/test_schema_conformance.py):
    python tests/test_intel_index.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from intel.build_index import build  # noqa: E402

FIXTURES = ROOT / "intel/fixtures"
REQUIRED_IOC_FIELDS = {"source", "family", "threat_type", "confidence", "first_seen", "tags"}
REQUIRED_HASH_FIELDS = REQUIRED_IOC_FIELDS | {"clamav", "signer", "issuer_cn", "cscb_listed"}


def _offline_index() -> dict:
    mb = json.loads((FIXTURES / "malwarebazaar_recent.json").read_text())
    tf = json.loads((FIXTURES / "threatfox_iocs.json").read_text())
    uh = (FIXTURES / "urlhaus_recent.csv").read_text()
    return build(tf, mb, uh, auth_key_id=None, days=7, offline=True)


def test_index_shape():
    idx = _offline_index()
    assert idx["index_version"] == "1.0.0"
    for table in ("domains", "ips", "hashes"):
        assert idx[table], f"{table} table is empty"
    assert idx["source_counts"] == {"malwarebazaar": 2, "threatfox": 4, "urlhaus": 2}
    for domain, rec in idx["domains"].items():
        assert domain == domain.lower()
        assert REQUIRED_IOC_FIELDS <= rec.keys(), rec
    for sha, rec in idx["hashes"].items():
        assert len(sha) == 64 and sha == sha.lower()
        assert REQUIRED_HASH_FIELDS <= rec.keys(), rec
    print(f"index shape OK  domains={len(idx['domains'])} ips={len(idx['ips'])} "
          f"hashes={len(idx['hashes'])}")


def test_cli_offline_build():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "v1"
        subprocess.run(
            [sys.executable, str(ROOT / "intel/build_index.py"),
             "--offline", "--fixtures", str(FIXTURES), "--out", str(out)],
            check=True, cwd=ROOT, capture_output=True)
        assert (out / "reputation.json").exists()
        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["offline"] is True
        assert manifest["auth_key_id"] is None
        assert manifest["counts"]["domains"] >= 1
    print("offline CLI build OK")


def test_grounded_dataset_is_conformant_and_separable():
    idx = _offline_index()
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "v4"
        # Build the index file inside the temp dir so the test is self-contained.
        idx_path = Path(tmp) / "reputation.json"
        idx_path.write_text(json.dumps(idx))
        subprocess.run(
            [sys.executable, str(ROOT / "data_synthetic/generate.py"),
             "--n-incidents", "120", "--seed", "7", "--out", str(data),
             "--intel", str(idx_path)],
            check=True, cwd=ROOT, capture_output=True)

        events = [json.loads(l) for l in (data / "events.jsonl").read_text().splitlines() if l.strip()]
        incidents = [json.loads(l) for l in (data / "incidents.jsonl").read_text().splitlines() if l.strip()]

        # Every incident carries the intel provenance, and only grounded values
        # appear on malicious incidents.
        real_domains = set(idx["domains"])
        real_hashes = set(idx["hashes"])
        by_inc = {}
        for e in events:
            by_inc.setdefault(e["incident_id"], []).append(e)

        grounded_malicious = 0
        for inc in incidents:
            assert inc["provenance"].get("intel_version") == "1.0.0", inc["incident_id"]
            has_real = any(
                (e.get("network", {}) or {}).get("domain") in real_domains
                or (e.get("file", {}) or {}).get("sha256") in real_hashes
                for e in by_inc[inc["incident_id"]]
            )
            if inc["label"] == "benign":
                assert not has_real, f"benign {inc['incident_id']} matched real intel"
            grounded_malicious += int(has_real)
        assert grounded_malicious > 0, "no malicious incident matched real intel"

    print(f"grounded dataset OK  malicious_with_real_intel={grounded_malicious}")


def test_schema_conformance_when_available():
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print("jsonschema not installed - skipping schema validation")
        return

    events_schema = json.loads((ROOT / "ml/schema/events.v1.json").read_text())
    incidents_schema = json.loads((ROOT / "ml/schema/incidents.v1.json").read_text())
    ev_val = Draft202012Validator(events_schema)
    in_val = Draft202012Validator(incidents_schema)

    idx = _offline_index()
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "v4"
        idx_path = Path(tmp) / "reputation.json"
        idx_path.write_text(json.dumps(idx))
        subprocess.run(
            [sys.executable, str(ROOT / "data_synthetic/generate.py"),
             "--n-incidents", "80", "--seed", "7", "--out", str(data),
             "--intel", str(idx_path)],
            check=True, cwd=ROOT, capture_output=True)
        errors = 0
        for line in (data / "events.jsonl").read_text().splitlines():
            if line.strip():
                errors += len(list(ev_val.iter_errors(json.loads(line))))
        for line in (data / "incidents.jsonl").read_text().splitlines():
            if line.strip():
                errors += len(list(in_val.iter_errors(json.loads(line))))
        assert errors == 0, f"{errors} schema violations in grounded output"
    print("grounded output conforms to both schemas")


if __name__ == "__main__":
    test_index_shape()
    test_cli_offline_build()
    test_grounded_dataset_is_conformant_and_separable()
    test_schema_conformance_when_available()
    print("\nall intel tests passed")
