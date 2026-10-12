# Taste
- Prefers grounding experiments in real, practical data sources (e.g. public threat-intel APIs like abuse.ch) rather than relying purely on synthetic data. Confidence: 0.5
- Wants analysis to produce durable artifacts: run experiments and persist results as rendered figures/graphs rather than one-off ad-hoc output. Confidence: 0.5
- When they explicitly name a data source/link, expects it to be used exactly as given — substituting another source (or a partial/intermediate use of theirs) must be surfaced and justified up front, not left implicit. Confidence: 0.6
- Prefers secrets/credentials kept in a local `.env` file (gitignored) rather than hardcoded or committed. Confidence: 0.6
- Wants a structured summary report of work completed — objective, what was built/added, what was modified, results, caveats/limitations, and what remains undone — rather than a terse change list. Confidence: 0.5
- Wants work write-ups delivered as standalone, shareable markdown report files in the repo (e.g. `report.md`), structured to be forwarded to a supervisor/third party — not just as chat answers. Confidence: 0.5
- When asking for a "summary"/report, actually wants the concrete measured results (the numbers, metrics, experiment tables) — not a description of what was built. Prefers pulling real values from the source (experiment logs) over paraphrasing. Confidence: 0.5
