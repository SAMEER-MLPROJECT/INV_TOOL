# Validation report

All numbers below were produced by running the commands shown in the build environment on **2026-10-31**
(Linux x86-64, Python 3.13.18, Node 22.23, Chromium via system Google Chrome). Nothing here is estimated.

## 1. How to reproduce

```bash
pip install -r requirements-dev.txt
cd backend
pytest -m "not e2e" --cov=attackgraph          # unit, integration, API, known-answer
AGL_CHROME=/path/to/chrome pytest -m e2e        # browser tests; needs frontend/dist
cd ../frontend && npm ci && npm run build       # TypeScript type-check + production build
python ../scripts/benchmark.py                  # timings
ruff check backend/attackgraph backend/tests scripts --select E,F,W,B,I --ignore E501,B008,B905,B007,E741
```

## 2. Results

| Check | Result |
|---|---|
| pytest (all, including 6 Playwright browser tests) | **105 passed, 0 failed, 0 skipped** |
| Statement coverage of `backend/attackgraph` | **95 %** (2,870 statements) |
| TypeScript `tsc -b` (strict) | **0 errors** |
| Vite production build | succeeds |
| ruff (E, F, W, B, I rule sets) | **all checks passed** |
| Sample-data generator determinism | byte-identical output on regeneration |

Defects found and fixed while testing (see DEVELOPMENT_LOG.md): a temporal-path model that let unrelated activity
days apart form a "path" (added the max-gap constraint and exact arrival-set propagation); blast-radius tiers that
labelled an admin's reach "suspected" because of someone else's malicious use of a shared server (added the
unbroken-chain rule); hub detection that wrongly excluded the compromised workstation (replaced seed-share heuristic
with infrastructure-degree hubs); a search-budget overrun of a few expansions; a UI font-size override; a first
containment planner that ranked actions by path membership and recommended blocking a logon that had already happened
(replaced by simulation-based selection, foothold modelling and redundancy pruning).

## 3. Coverage of the required test areas

| Required area | Tests |
|---|---|
| Input validation / invalid data | `test_ingest.py::test_csv_ingestion_validation_duplicates_and_conflicts`, `test_file_level_rejections`, `test_inventory_validation`, `test_normalize.py::test_invalid_timestamps_rejected` |
| CSV ingestion | `test_csv_ingestion_validation_duplicates_and_conflicts`, sample-dataset tests |
| JSON / JSONL ingestion | `test_json_array_object_and_jsonl_formats`, `test_source_hint_overrides_detection_and_alert_mapping` |
| Timestamp / UTC normalisation | `test_timestamps_normalized_to_utc` (ISO Z, +05:30, naive, epoch s/ms) |
| Entity extraction & de-duplication | `test_graph.py::test_entities_extracted_and_deduplicated`, `test_identifier_normalization` |
| Relationship creation & provenance | `test_relationships_and_provenance`, `test_ip_resolution_is_marked_inferred`, `test_every_occurrence_traces_to_an_event_and_rule` |
| Temporal ordering | `test_occurrences_are_time_ordered`, `test_known_answer_path_user_ws_srv_db` (chronological steps) |
| Directed path discovery (known answer) | `test_known_answer_path_user_ws_srv_db`: USER-01 → WS-01 → SRV-01 → DB-01 with events E1, E3, E4 |
| Temporally impossible paths | `test_temporally_impossible_path_is_rejected_with_reason`, `test_max_gap_between_steps`, `test_backup_route_rejected_as_temporally_impossible` |
| Hop-limit enforcement | `test_hop_limit_enforced`, `test_hop_validation`, `test_temporal_mode_uses_only_time_respecting_routes` |
| Blast-radius accuracy | `test_temporal_mode_uses_only_time_respecting_routes` (DB-01 at hop 3 via WS-01→SRV-01, arrival 10:20), `test_evidence_tiers_and_analyst_confirmation`, `test_blast_radius_distinguishes_attack_from_admin` |
| Incident grouping | `test_correlation.py` (grouping, window configurability, benign dampening, source counting), `test_sample_incidents` |
| Evidence provenance | `test_api.py::test_evidence_endpoints`, `test_relationships_and_provenance` |
| Cycles | `test_cycles_are_represented`, `test_cycles_do_not_loop` |
| Empty datasets | `test_empty_dataset`, `test_empty_file_is_a_warning_not_a_crash` |
| Export consistency | `test_report_export_consistency_and_manifest` (JSON report = API incident; Markdown carries every source hash; HTML has no script; export hash appears in manifest; manifest hashes = file hashes) |
| API | `test_api.py` (10 tests: status codes, filters, uploads, settings validation, analyst status, error hiding, Neo4j 409) |
| Security behaviours | traversal-safe filenames, oversize upload 413, executable upload rejected, stack traces hidden, Cypher injection stays in parameters, credentials absent from error messages |
| Neo4j adapter | `test_neo4j_adapter.py` (6 tests, recording fake driver: **not** a live database) |
| Essential frontend interactions | `test_e2e_ui.py` (overview → incident, path search + evidence inspector, blast hop slider, report download + settings health; asserts no page errors) |
| Search limits | `test_search_budget_marks_truncation` |
| Multichannel corroboration | `test_novelty.py::test_principal_path_is_corroborated_across_channels`, `test_silent_channel_detected_on_credential_theft_step`, `test_incident_channel_matrix_flags_single_channel_evidence` |
| MD deviation | `test_chi_square_reference`, `test_md_deviation_flags_attack_records_and_explains_them` (contributions sum to D²), `test_md_deviation_alone_never_crosses_suspicion_threshold` |
| Real-time live mode | `test_live.py` (push API provenance and de-duplication, validation, version on every rebuild, replay builds the Critical incident and SUSPECTED FINANCE-DB, stop, Server-Sent Events), e2e `test_live_replay_updates_the_ui` |
| Containment / what-if (known answers) | `test_counterfactual_removes_only_prevented_occurrences`, `test_what_if_isolating_server_protects_database`, `test_plan_at_first_alert_is_single_isolation`, `test_plan_after_credential_theft_needs_more_than_the_workstation`, `test_novelty_api`, e2e `test_containment_and_multichannel_panels` |

## 4. Measured timings (synthetic dataset)

`python scripts/benchmark.py`: median of 5 runs; dataset 1,191 events, 349 entities, 968 relationships, 1,625
occurrences.

| Operation | Median (ms) |
|---|---|
| Ingest 7 files + build graph (incl. MD scoring) | 88.2 |
| Correlate alerts into incidents | 6.7 |
| Paths sameer → FINANCE-DB (5 hops) | 2.3 |
| Paths sameer → all critical assets (8 hops) | 6.3 |
| Blast radius sameer (4 hops, temporal) | 0.4 |
| Blast radius WS-014 (8 hops, structural) | 0.4 |
| MD deviation scoring (all occurrences) | 14.0 |
| Multichannel analysis of INC-0002 | 0.2 |
| Containment plan INC-0002 at first alert | 279.1 |
| Containment plan INC-0002 at 21:10Z | 417.9 |

These describe this prototype on this small dataset and machine only. No claim is made about throughput or latency on
enterprise-scale data; see LIMITATIONS.md.

## 5. What was *not* measured

- **Detection accuracy, precision, recall, F1**: not computed. The only labelled data is the synthetic dataset whose
  answers were written by the generator; a score on it would be circular.
- **User feedback**: none collected.
- **Real-world deployment**: none.
- **Neo4j/AuraDB, Docker image, GitHub Actions**: files exist and the adapter is unit-tested, but none of these were
  executed against the real service in this environment.

## 6. Known weaknesses found during validation

- Process nodes dominate entity counts (265 of 349); the UI collapses them in the blast-radius view, but very large
  EDR feeds would need aggregation.
- Correlation uses pairwise comparison inside the window; dense alert storms would need indexing.
- The max-gap default (6 h) suits fast intrusions; slow, multi-day campaigns need it raised (or set to 0).
- Weights are expert-chosen and only sanity-checked on synthetic data.
- Containment planning re-runs path and blast searches per candidate (hundreds of milliseconds here); larger graphs
  would need incremental recomputation.
- The MD baseline is three days of synthetic activity; with so little history, routine-but-rare events (nightly
  backups) deviate strongly. The cap below the threshold is what keeps this from producing false "suspected" labels.

## 7. Test list (last run)

- `tests/test_api.py::test_health_summary_and_security_headers`: PASSED
- `tests/test_api.py::test_paths_blast_incident_endpoints`, PASSED
- `tests/test_api.py::test_evidence_endpoints`, PASSED
- `tests/test_api.py::test_graph_endpoint_filters`, PASSED
- `tests/test_api.py::test_upload_valid_invalid_and_traversal`: PASSED
- `tests/test_api.py::test_settings_validation_and_recompute`, PASSED
- `tests/test_api.py::test_analyst_status`, PASSED
- `tests/test_api.py::test_report_export_consistency_and_manifest`: PASSED
- `tests/test_api.py::test_internal_errors_hide_stack_traces`, PASSED
- `tests/test_api.py::test_neo4j_sync_requires_configuration`, PASSED
- `tests/test_blast.py::test_structural_blast_radius_uses_shortest_hop`: PASSED
- `tests/test_blast.py::test_temporal_mode_uses_only_time_respecting_routes`: PASSED
- `tests/test_blast.py::test_hop_validation`, PASSED
- `tests/test_blast.py::test_evidence_tiers_and_analyst_confirmation`: PASSED
- `tests/test_blast.py::test_growth_curve_is_cumulative`, PASSED
- `tests/test_cli.py::test_analyze_and_path_commands`, PASSED
- `tests/test_cli.py::test_env_file_loader`, PASSED
- `tests/test_correlation.py::test_related_alerts_grouped_unrelated_kept_apart`: PASSED
- `tests/test_correlation.py::test_correlation_window_is_configurable`: PASSED
- `tests/test_correlation.py::test_benign_disposition_reduces_priority`: PASSED
- `tests/test_correlation.py::test_independent_sources_counted_by_system_not_record`: PASSED
- `tests/test_correlation.py::test_sample_incidents`, PASSED
- `tests/test_e2e_ui.py::test_overview_to_incident_flow`, PASSED
- `tests/test_e2e_ui.py::test_path_explorer_finds_and_explains`, PASSED
- `tests/test_e2e_ui.py::test_blast_radius_hop_slider_updates`, PASSED
- `tests/test_e2e_ui.py::test_report_download_and_settings`, PASSED
- `tests/test_e2e_ui.py::test_containment_and_multichannel_panels`: PASSED
- `tests/test_e2e_ui.py::test_live_replay_updates_the_ui`, PASSED
- `tests/test_graph.py::test_entities_extracted_and_deduplicated`: PASSED
- `tests/test_graph.py::test_relationships_and_provenance`, PASSED
- `tests/test_graph.py::test_ip_resolution_is_marked_inferred`, PASSED
- `tests/test_graph.py::test_failed_logons_and_blocked_flows_create_no_edges`: PASSED
- `tests/test_graph.py::test_cycles_are_represented`, PASSED
- `tests/test_graph.py::test_occurrences_are_time_ordered`, PASSED
- `tests/test_graph.py::test_every_occurrence_traces_to_an_event_and_rule`: PASSED
- `tests/test_graph.py::test_empty_dataset`, PASSED
- `tests/test_ingest.py::test_csv_ingestion_validation_duplicates_and_conflicts`: PASSED
- `tests/test_ingest.py::test_json_array_object_and_jsonl_formats`: PASSED
- `tests/test_ingest.py::test_file_level_rejections`, PASSED
- `tests/test_ingest.py::test_empty_file_is_a_warning_not_a_crash`: PASSED
- `tests/test_ingest.py::test_filename_sanitization_prevents_traversal[../../etc/passwd.csv-passwd.csv]`: PASSED
- `tests/test_ingest.py::test_filename_sanitization_prevents_traversal[..\\..\\windows\\evil.csv-evil.csv]`: PASSED
- `tests/test_ingest.py::test_filename_sanitization_prevents_traversal[normal`: file
- `tests/test_ingest.py::test_filename_sanitization_prevents_traversal[.hidden.json-hidden.json]`: PASSED
- `tests/test_ingest.py::test_record_without_id_gets_deterministic_hash`: PASSED
- `tests/test_ingest.py::test_source_hint_overrides_detection_and_alert_mapping`: PASSED
- `tests/test_ingest.py::test_inventory_validation`, PASSED
- `tests/test_live.py::test_pushed_records_enter_the_graph_with_stream_provenance`: PASSED
- `tests/test_live.py::test_stream_validation`, PASSED
- `tests/test_live.py::test_every_rebuild_publishes_a_version`, PASSED
- `tests/test_live.py::test_replay_streams_the_attack_and_the_picture_builds_up`: PASSED
- `tests/test_live.py::test_replay_can_be_stopped`, PASSED
- `tests/test_live.py::test_server_sent_events_and_push_endpoint`: PASSED
- `tests/test_neo4j_adapter.py::test_requires_credentials`, PASSED
- `tests/test_neo4j_adapter.py::test_sync_is_batched_and_parameterised`, PASSED
- `tests/test_neo4j_adapter.py::test_injection_attempt_stays_in_parameters`: PASSED
- `tests/test_neo4j_adapter.py::test_hop_bound_validated[0]`, PASSED
- `tests/test_neo4j_adapter.py::test_hop_bound_validated[9]`, PASSED
- `tests/test_neo4j_adapter.py::test_hop_bound_validated[3;`, DROP]
- `tests/test_neo4j_adapter.py::test_hop_bound_validated[2.5]`, PASSED
- `tests/test_neo4j_adapter.py::test_workspace_sync_and_neo4j_backed_path_search`: PASSED
- `tests/test_neo4j_adapter.py::test_connection_failure_reports_class_not_secret`: PASSED
- `tests/test_normalize.py::test_timestamps_normalized_to_utc[2026-10-27T20:40:00Z-expected0-None]`, PASSED
- `tests/test_normalize.py::test_timestamps_normalized_to_utc[2026-10-28T02:10:00+05:30-expected1-offset]`, PASSED
- `tests/test_normalize.py::test_timestamps_normalized_to_utc[2026-10-27`: 20:40:00-expected2-no
- `tests/test_normalize.py::test_timestamps_normalized_to_utc[1793133600-expected3-None]`: PASSED
- `tests/test_normalize.py::test_timestamps_normalized_to_utc[1793133600000-expected4-None]`: PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[None]`, PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[]`, PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[not-a-time]`: PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[1899-01-01T00:00:00Z]`, PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[2026-13-01T00:00:00Z]`, PASSED
- `tests/test_normalize.py::test_invalid_timestamps_rejected[bad5]`, PASSED
- `tests/test_normalize.py::test_identifier_normalization`, PASSED
- `tests/test_normalize.py::test_severity_scales`, PASSED
- `tests/test_normalize.py::test_internal_vs_external_addresses`, PASSED
- `tests/test_novelty.py::test_principal_path_is_corroborated_across_channels`: PASSED
- `tests/test_novelty.py::test_silent_channel_detected_on_credential_theft_step`: PASSED
- `tests/test_novelty.py::test_incident_channel_matrix_flags_single_channel_evidence`: PASSED
- `tests/test_novelty.py::test_chi_square_reference`, PASSED
- `tests/test_novelty.py::test_md_deviation_flags_attack_records_and_explains_them`: PASSED
- `tests/test_novelty.py::test_md_deviation_alone_never_crosses_suspicion_threshold`: PASSED
- `tests/test_novelty.py::test_counterfactual_removes_only_prevented_occurrences`: PASSED
- `tests/test_novelty.py::test_what_if_isolating_server_protects_database`: PASSED
- `tests/test_novelty.py::test_action_validation`, PASSED
- `tests/test_novelty.py::test_plan_at_first_alert_is_single_isolation`: PASSED
- `tests/test_novelty.py::test_plan_after_credential_theft_needs_more_than_the_workstation`: PASSED
- `tests/test_novelty.py::test_novelty_api`, PASSED
- `tests/test_paths.py::test_known_answer_path_user_ws_srv_db`, PASSED
- `tests/test_paths.py::test_temporally_impossible_path_is_rejected_with_reason`: PASSED
- `tests/test_paths.py::test_hop_limit_enforced`, PASSED
- `tests/test_paths.py::test_relationship_filter`, PASSED
- `tests/test_paths.py::test_since_excludes_earlier_activity`, PASSED
- `tests/test_paths.py::test_cycles_do_not_loop`, PASSED
- `tests/test_paths.py::test_unknown_entities_raise`, PASSED
- `tests/test_paths.py::test_auto_targets_are_critical_assets`, PASSED
- `tests/test_paths.py::test_search_budget_marks_truncation`, PASSED
- `tests/test_paths.py::test_max_gap_between_steps`, PASSED
- `tests/test_paths.py::test_candidate_provider_results_are_temporally_validated`: PASSED
- `tests/test_sample_dataset.py::test_ingestion_flags_planted_bad_records`: PASSED
- `tests/test_sample_dataset.py::test_principal_attack_path`, PASSED
- `tests/test_sample_dataset.py::test_backup_route_rejected_as_temporally_impossible`: PASSED
- `tests/test_sample_dataset.py::test_blast_radius_distinguishes_attack_from_admin`: PASSED
- `tests/test_sample_dataset.py::test_unmanaged_ip_kept_as_ip_entity`, PASSED
- `tests/test_sample_dataset.py::test_generator_is_deterministic`, PASSED
