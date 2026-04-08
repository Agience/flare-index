# FLARE — Working Agreement

This file is loaded automatically into every Claude Code session in this repo. It encodes the durable working agreement for FLARE.

## Final deliverables

1. **A working prototype.** The `flare` Python package with the `make showcase`, `make demo`, `make demo-compose`, `make bench`, and `make bench-real` targets all green.
2. **A research paper** at `paper/flare.md` whose every empirical claim is backed by a reproducible artifact in `paper/evals/` and whose every design claim traces to code in `flare/`.
3. **A consolidated security risk register** at `docs/analysis/security.md` that a reviewer can read end-to-end.

Both deliverables move together. Neither is finished while the other lags.

## Working rules

1. **FLARE is a single coherent product.** When writing the paper, the README, code docstrings, or any user-facing prose, describe FLARE as one finished system. The development was incremental but the writing should not be — readers care about what the system *is*, not the order pieces were built. Avoid "Phase 1 added X, Phase 4 added Y" framing in the paper, README, code docstrings, and the consolidated `security.md`. The per-phase findings files are kept as historical changelogs but are not the canonical reference.
2. **Code + analysis + paper move together.** A change is not "done" until:
   - the code change is merged and `make test` is green,
   - any new security observation is recorded in `docs/analysis/security.md` with severity, file:line, status, and a test pointer where applicable,
   - the paper's relevant section reflects the change (or a follow-up `paper/CHANGELOG.md` entry says why it doesn't),
   - if the change touches what users see, the README is updated.
3. **Security/implementation analysis is an active task, not a retrospective.** While writing code, flag risks inline as `# ANALYSIS:` comments referencing `docs/analysis/security.md`, then transfer them into the register in the same change. Do not batch analysis to the end.
4. **Everything runs in Docker.** No host-side installs. New services go in `docker-compose.yml`, not in README setup steps. The Makefile targets are the canonical entry points.
5. **Honest framing.** The paper must not overclaim. If something is stubbed, the paper says so in §Implementation and carries the limitation into §Limitations. A reviewer must never be surprised by the gap between claims and code.
6. **Real benchmarks.** Empirical claims about retrieval quality must use a real dataset (currently BEIR SciFact in `bench/bench_real_data.py`), not synthetic vectors. Synthetic numbers are fine for *latency* benches because the latency is independent of the data, but recall claims must come from real data.
7. **Reproducibility.** Every number cited in the paper must be reproducible by running a `make` target. The bench scripts write to `paper/evals/` so the source of truth is the JSON, not the prose.
8. **Repo hygiene.** Use the dedicated tools (Read/Edit/Write/Glob/Grep), not bash equivalents. Keep modules small and named after the concept they implement.
