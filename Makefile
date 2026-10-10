# SentinelLLM - Person 2 (AI/ML/multimodal). One command reproduces everything.
PY := ./.venv/bin/python
DATA := data_synthetic/v1
SEED := 7
N := 400
NO_RULES := static,temporal,graph,network,visual,corroboration

.PHONY: all setup data features test baselines ablation clean reproduce

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
