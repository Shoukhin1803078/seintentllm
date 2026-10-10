# Feature dictionary

Generated from `data_synthetic/v3` - 800 incidents, 58 features.

## corroboration (4 features)
- `corroboration__n_detections`
- `corroboration__any_malicious_verdict`
- `corroboration__max_confidence`
- `corroboration__n_distinct_sources`

## graph (5 features)
- `graph__max_tree_depth`
- `graph__mean_tree_depth`
- `graph__n_distinct_proc_names`
- `graph__n_proc_events`
- `graph__proc_name_reuse`

## network (9 features)
- `network__n_connections`
- `network__max_domain_rarity`
- `network__mean_domain_rarity`
- `network__n_rare_domains`
- `network__n_distinct_domains`
- `network__total_bytes_out`
- `network__max_bytes_out`
- `network__n_bad_reputation`
- `network__min_domain_age_days`

## rules (13 features)
- `rules__R001`
- `rules__R002`
- `rules__R003`
- `rules__R004`
- `rules__R005`
- `rules__R006`
- `rules__R007`
- `rules__R008`
- `rules__R009`
- `rules__R010`
- `rules__R011`
- `rules__R012`
- `rules__n_distinct`

## static (14 features)
- `static__n_unsigned_proc`
- `static__frac_unsigned_proc`
- `static__n_untrusted_signer_proc`
- `static__n_temp_proc`
- `static__n_unsigned_temp_proc`
- `static__n_new_files`
- `static__n_unknown_prevalence`
- `static__n_encrypted_archive`
- `static__max_name_entropy`
- `static__mean_name_entropy`
- `static__max_cmdline_len`
- `static__n_credential_access`
- `static__n_distinct_cred_stores`
- `static__n_persistence_writes`

## temporal (9 features)
- `temporal__duration_s`
- `temporal__n_events`
- `temporal__median_gap_s`
- `temporal__min_gap_s`
- `temporal__gap_stdev_s`
- `temporal__events_per_min`
- `temporal__burstiness`
- `temporal__exec_to_egress_s`
- `temporal__has_exec_then_egress`

## visual (4 features)
- `visual__n_screenshots`
- `visual__deceptive_text_cues`
- `visual__has_clipboard_write`
- `visual__screenshot_then_exec`
