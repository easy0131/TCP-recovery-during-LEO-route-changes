# CS30401 Lab 1 — TCP recovery during LEO route changes

Authors: Junhui Kim, Jio Lee, Woojin Lim. Team ID: **6**.

## 1. Environment and execution

Use `ghcr.io/yeonjong21/cs30401-lab1:2026f-v1` (linux/amd64). Validation recorded image ID `sha256:3cb4877c73b4ae5e3542c1567b6761a8913056dd429d8a18f7c40aeeb399b3b4` and Docker server 28.0.4. Start with a new ns-3 volume mounted at `/home/ubuntu/ns-3.48`; mount the extracted submission root at `/work`. Allow the course image initialization to complete.

Example from PowerShell in the extracted submission directory (use a new volume/container name if these already exist):

```powershell
docker run -it --name lab1-submit-check -v lab1-submit-ns3:/home/ubuntu/ns-3.48 -v "${PWD}:/work" ghcr.io/yeonjong21/cs30401-lab1:2026f-v1
```

Inside the initialized container:

```bash
cd /work/code
bash run_all.sh --smoke
bash run_all.sh
```

Smoke runs London baseline and Latest. The full workflow rechecks completed smoke results and executes the remaining cases: 35 improvement cases, seven baselines, and four queue cases, totaling **46 distinct cases**. It verifies the package, installs locked plotting dependencies, applies the included course-exported patch to clean ns-3 sources, builds, generates states, runs simulations, checks results, and generates tables/figures. A completed case is reused only after checks; failed/partial outputs are preserved and cause a stop.

The course supplies ns-3.48, Hypatia, and state-generator dependencies. Plotting uses `code/pyproject.toml` and `uv.lock`; initial `uv sync --frozen` requires network access unless cached. `run_all.sh` selects the course Python interpreter and the runner invokes plotting via `uv run --frozen python`.

The validated runner supports `--smoke`; it does **not** expose `--state-jobs` or `--jobs`. Sequential city preparation is the documented default. During validation, separate processes prepared distinct cities, each generator retaining `--threads 1`. Do not launch concurrent preparation for the same city. Windows bind mounts can make repeated small-file checks slow; validation moved the same workspace to a native Docker volume at the same `/work` path before resuming, without changing experiment data or controls.

Allow roughly **3.5–4.5 hours plus setup/build overhead** for a sequential run; this remains a planning estimate, not a benchmark. Recorded city generation/check intervals were approximately 16–30 minutes (London about 21.5 minutes, estimated from log timestamps). The complete validation session lasted approximately 4 h 29 min including debugging, waits and workspace relocation, so it is not a clean end-to-end runtime measurement.

## 2. Generated inputs and compatibility fixes

The constellation has 1,584 satellites; routing updates every 100 ms. ISL/GSL links use 100 Mbps. Experiments use one 100-GB CUBIC flow from node 1584 to 1585, MSS 1,380 bytes, and seed 123456789. Queue runs use 100/250/500/1,000 packets for 60 seconds. Route comparisons retain q100.

States are generated for 200 seconds using the bundled generator snapshot and per-city station coordinates in `state_reference.json`; generated states are not included. New York intentionally retains its original slightly different Seoul coordinate. Explicit generation, if needed:

```bash
cd /work/code
python3 candidate_support.py states london
# Omit city names to generate and verify all seven cities.
```

All 4,005 simulator-input files per city must match reference SHA-256 values. The helper preserves the original absolute simulator input paths and refuses conflicting existing files.

The submitted helper contains two fixes made during validation:

1. It respects the image's `SATGENPY` variable, falling back to `$LAB/../hypatia/satgenpy`, rather than forcing an incorrect directory below `$LAB`.
2. At London's 100-s routing snapshot, freshly generated deltas and the historical full snapshot encode the same routing table. The helper reconstructs the full table from freshly generated deltas and changes its representation only if that reconstruction exactly matches the expected snapshot hash. It preserves the original delta and a receipt. Other mismatches still stop execution. No reference hash, metric target, or ns-3 algorithm source was altered by these fixes.

The fixed event inputs represent exact route forecasts and instantaneous queue information. Baseline disables experimental interventions in the same instrumented binary. Undo is matched **CUBIC-only** restoration with an external transition trigger. Latest is `queue_guard_undo`, which includes revised preventive control; it is not merely the earlier v5 plus full undo.

## 3. Report-to-output mapping

Run commands below inside `/work/code`, after the required simulations. The full workflow invokes them automatically.

| Report item | Command | Generated evidence |
|---|---|---|
| Startup RTO and London/New York packet diagnosis | `python3 diagnose.py` | `generated/report/packet_diagnosis.json` |
| Table I; Fig. 2 queue tradeoff | `uv run --frozen python queue_runs.py analyze` | `generated/queues/analysis/generated/queue_summary.csv`, `results.json`, `queue_tradeoff.png`; `generated/queues/reference_check.json` |
| Table II; Fig. 3 route comparison | `python3 reproduce_baseline.py analyze` then `uv run --frozen python render_results.py` | `generated/report/route_table.md`, `route_comparison.csv`, `route_ack_rate.pdf` |
| Fig. 1 London transition | Same renderer | `generated/report/london_transition.pdf` |
| Table III deployment comparison | Same analysis/renderer | London baseline/undo/queue_guard_undo event10 ACK and event2 LastRTT rows in `reproduced_baseline/all_replayed_metrics.csv`; requirements are described in report Section III |
| Delay criteria and restoration activations | Same renderer | `generated/report/latest_diagnostics.json`, `reproduced/results.json` |

Fig. 1 uses the fresh-state validation PDF. Figs. 2–3 in the report restyle generated numeric results for column width and grayscale readability; the runtime plots may differ visually but use the same observations. Table II and its display plot round ACK rates to three decimals. Exact historical cwnd samples quoted in Section II.B originate in the original q100 trace; fresh packet diagnosis independently identifies the two genuine-loss retransmissions before the transition and 28 unnecessary retransmissions after it.

ACK throughput measures newly acknowledged payload per interval, not an independent receiver goodput trace. Route throughput uses ten seconds after the nominal transition; delay uses two-second time-weighted LastRTT p95. Queue analysis uses time-weighted SRTT in separate 0–60 and 20–60-s intervals. Whole-run intervals differ by route. Multiple trace hooks are not summed as independent packet losses.

## 4. Manila criterion and provenance

The team's recorded selection workflow compares delay against **110% of both v5 and auto_watch_undo**, testing regression against existing methods. Relevant source records are `code/provenance/manila_selection_plan.json`, `manila_frozen_plan.json`, and `manila_heldout_source.py`. These document selection/freeze before the performance step; historical execution order has not been independently audited.

Latest's two-second LastRTT p95 is 31 ms, above the binding 30.8-ms limit, so the recorded **performance criterion fails**. Against baseline's 29 ms the increase is 2 ms (6.90%), below a separate descriptive 31.9-ms bound; this does not replace the original criterion. Integer-ms resolution is disclosed without changing the decision. Tokyo is a development repair, not independent held-out confirmation. Latest restoration applies zero times in all seven cities. Reproduction PASS therefore does not imply every method passes its performance criterion or generalizes to every route.

## 5. Completed verification

On 12 October 2026, Woojin Lim validated the corrected package from generated states:

- 28,035 simulator-input file hashes matched across seven cities.
- All 35 improvement cases matched 350 transport-trace hashes and 105 metric-window dictionaries.
- Seven baselines passed inactive-control/configuration checks, pre-intervention prefix checks against each method, and reference metrics.
- Four queue cases matched throughput/SRTT references, with no mismatches.
- Runtime output ended with `PASS candidate workflow 42 route cases + 4 queue cases`.
- The official course `make_patch.sh` exported the nine-path patch. It applied and built in a second clean ns-3 volume, with all nine final source hashes matching.
- Table I and Table II values matched generated results at the report's displayed precision.

The two smoke cases were reused/rechecked in the full workflow, not counted twice. Earlier 18-case checks are historical evidence and are not added to the 46 as independent samples. Each case uses one deterministic seed. A third-volume rerun of the final exported ZIP was not performed; the exported files were checked against the sealed manifest instead.

The submitted `code/` files are byte-for-byte the verified export. Its 155 declared files pass SHA-256 checks, and the incoming verified ZIP passed CRC checks; original ZIP SHA-256: `563e14d1f7959cad205c9082a3589972c9d12720fcf2eee00a2a4f7cf9b42690`. `package_manifest.json` checks code integrity; `course_patch_provenance.json` records patch export. The provenance receipt's historical wording about a required forward test describes the export-time state; the later second-volume build completed that check.

## 6. Submission contents and updates

The submission contains only `report.pdf`, this `README.md`, and `code/`. Raw logs, generated routing states, binaries, caches, virtual environments, validation evidence archives, and development backups are excluded. The evidence archive is retained separately by the team.

To update scientific results, record the code/configuration change, execute in a fresh workspace, regenerate analysis, and update report values from that output. Never change expected hashes or metrics merely to hide a mismatch. The separate IEEE source companion contains the editable report, figure inputs, and PDF build instructions; it is not required to run the simulations.

## 7. Reused code and team additions

This project builds on the course-provided ns-3.48/Hypatia environment and the `scratch/main_satnet/main_satnet.cc` simulation entry point. We modify the existing ns-3 TCP socket, CUBIC, and IPv4 implementations (`tcp-socket-base.{cc,h}`, `tcp-cubic.{cc,h}`, and `ipv4-l3-protocol.{cc,h}`); the patch records these changes rather than claiming those components as original team code. The new `handover.h` and `lab1_packet_hops.h` files provide team transition-control and packet-diagnostic functionality. Team additions also include conditional CUBIC-state restoration, experiment runners, diagnostics, and analysis/reproduction scripts; state generation uses the course Hypatia dependency and its orbital/routing infrastructure.

### Code map

- `run_all.sh`, `run_all.py`, `reproduce*.py`, `candidate_support.py`: validated execution, baseline comparison, build and state preparation.
- `adaptive_handover_v1/`, `adaptive_handover_v2/`, `adaptive_handover_v5/`, `route_policy_pilot/`, `route_timing_pilot/`: retained analysis dependencies from successive team prototypes; v5 also contains the state-generation entry point.
- `v5_undo_hybrid/` and the other method-specific directories: fixed configurations, method evidence, and shared analysis for the compared controllers.
- `diagnose.py`, `team_share_recheck/`: packet/RTO diagnosis. The pipeline imports `rto_proof` and its helpers from the historical script; it does not execute that script's standalone analysis entry point. A Windows archive path in its historical case-analysis branch is not reached by the pipeline's `rto_proof` call.
- `render_results.py`, `queue_runs.py`, `analyze_queue_delay.py`: report metrics, plots, and queue comparisons. Use the top-level workflow rather than running historical standalone scripts directly.
