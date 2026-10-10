"""Every generated record must validate against the published contract.
If this fails, either the generator or the schema drifted - fix before modelling."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def _load(p):
    return [json.loads(l) for l in (ROOT / p).read_text().splitlines() if l.strip()]


def test_events_and_incidents_conform():
    ev_schema = json.loads((ROOT / "ml/schema/events.v1.json").read_text())
    inc_schema = json.loads((ROOT / "ml/schema/incidents.v1.json").read_text())
    events = _load("data_synthetic/v3/events.jsonl")
    incidents = _load("data_synthetic/v3/incidents.jsonl")

    ev_v, inc_v = Draft202012Validator(ev_schema), Draft202012Validator(inc_schema)
    errs = []
    for e in events:
        errs += [f"event {e.get('event_id')}: {x.message}" for x in ev_v.iter_errors(e)]
    for i in incidents:
        errs += [f"incident {i.get('incident_id')}: {x.message}" for x in inc_v.iter_errors(i)]
    assert not errs, "\n".join(errs[:20])

    # Referential integrity: incident event_ids must exist, and every event must
    # belong to a declared incident. The LLM grounding check depends on this.
    ids = {e["event_id"] for e in events}
    for i in incidents:
        missing = set(i["event_ids"]) - ids
        assert not missing, f"{i['incident_id']} references unknown events {missing}"
    declared = {eid for i in incidents for eid in i["event_ids"]}
    assert declared == ids, f"{len(ids - declared)} orphan events"

    # Privacy invariants from proposal section 15.
    for e in events:
        if "credential_target" in e:
            assert e["credential_target"]["secrets_collected"] is False
        if "visual" in e:
            assert e["visual"]["input_fields_redacted"] is True
        if "registry" in e and e["registry"].get("is_persistence_location"):
            assert e["registry"]["value_redacted"] is True
    print(f"OK: {len(events)} events, {len(incidents)} incidents conform")


if __name__ == "__main__":
    test_events_and_incidents_conform()
