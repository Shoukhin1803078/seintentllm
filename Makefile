# SentinelLLM - Person 2 (AI/ML/multimodal). One command reproduces everything.
PY := ./.venv/bin/python
DATA := data_synthetic/v1
SEED := 7
N := 400
NO_RULES := static,temporal,graph,network,visual,corroboration
INTEL := data_real/intel/v1/reputation.json
DATA_INTEL := data_synthetic/v4

.PHONY: all setup data features test baselines ablation clean reproduce \
        intel intel-offline data-intel features-intel intel-test figures intel-experiment

reproduce: data features test baselines ## full pipeline from scratch
	@echo "--- experiments logged to reports/experiments.csv ---"

setup:
	python3 -m venv .venv && $(PY) -m pip install -q --upgrade pip && \
	$(PY) -m pip install -q -r requirements.txt

data:
	$(PY) data_synthetic/generate.py --n-incidents $(N) --seed $(SEED) --out $(DATA)

features:
	$(PY) analysis/features.py --data $(DATA) --out reports/features.csv

test:
	$(PY) tests/test_schema_conformance.py

baselines:
	$(PY) ml/baseline.py --model rules --split time --note "s8 weights"
	$(PY) ml/baseline.py --model lr --groups rules --split time --note "rules-as-features"
	$(PY) ml/baseline.py --model lr --groups $(NO_RULES) --split time --note "no rule features"
	$(PY) ml/baseline.py --model rf --groups $(NO_RULES) --split time --note "no rule features"

ablation:
	@for sp in time random family; do \
	  for cfg in "rules:rules" "lr:rules" "lr:$(NO_RULES)" "rf:$(NO_RULES)" "rf:all"; do \
	    m=$${cfg%%:*}; g=$${cfg#*:}; \
	    $(PY) ml/baseline.py --model $$m --groups $$g --split $$sp --note "ablation" >/dev/null; \
	  done; done
	@echo "ablation complete - see reports/experiments.csv"

clean:
	rm -rf $(DATA)/events.jsonl $(DATA)/incidents.jsonl reports/features.csv

# --- abuse.ch intel (opt-in; see intel/README.md, docs/intel.md) --------------
intel-offline: ## build reputation index from committed fixtures (no key, no network)
	$(PY) intel/build_index.py --offline --out data_real/intel/v1

intel: ## build reputation index from live abuse.ch feeds (needs ABUSECH_AUTH_KEY)
	$(PY) intel/build_index.py --out data_real/intel/v1

data-intel: ## generate a v4 dataset grounded in real abuse.ch indicators
	@test -f $(INTEL) || { echo "missing $(INTEL) - run 'make intel' (live) or 'make intel-offline' (fixtures)"; exit 1; }
	$(PY) data_synthetic/generate.py --n-incidents $(N) --seed $(SEED) \
		--out $(DATA_INTEL) --intel $(INTEL)

features-intel: data-intel ## feature table including the `intel` group
	$(PY) analysis/features.py --data $(DATA_INTEL) --intel $(INTEL) \
		--out reports/features_intel.csv

intel-test:
	$(PY) tests/test_intel_index.py

intel-experiment: features-intel ## log +/- intel baselines on the grounded dataset
	$(PY) ml/baseline.py --features reports/features_intel.csv --data $(DATA_INTEL) \
		--model rf --groups $(NO_RULES) --split time --note "v4 grounded, no intel features"
	$(PY) ml/baseline.py --features reports/features_intel.csv --data $(DATA_INTEL) \
		--model rf --groups $(NO_RULES),intel --split time --note "v4 grounded, + intel features"

figures: ## render every result figure whose inputs are available
	$(PY) analysis/make_figures.py
