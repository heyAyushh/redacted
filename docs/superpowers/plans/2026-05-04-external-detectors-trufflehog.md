# External Detector Engines Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit external detector engine path so `redacted detector install trufflehog`, `redacted detector use trufflehog`, and `redacted --detectors --input ...` work end to end.

**Architecture:** Native Rust detectors remain always-on and unchanged. External detector engines are lower-trust optional adapters that run only for `--input` scans when forced with `--detectors` or enabled persistently with `redacted detector default on`; the TruffleHog adapter runs the local `trufflehog` CLI as a separate process and maps its JSON output into normal `redacted` findings.

**Tech Stack:** Rust standard library only in the core CLI, local TruffleHog CLI as an optional external executable, existing app config/data state helpers, existing report/redaction pipeline.

---

## File Map

- Modify `src/cli.rs`: add `detector` command parsing/help plus `--detectors` and `--no-detectors`.
- Modify `src/config.rs`: carry explicit external-detector mode from CLI into runtime config.
- Create `src/external_detector.rs`: catalog, install/use/default/current/list/verify/disable, TruffleHog process runner, JSON result parsing, and finding conversion.
- Modify `src/main.rs`: invoke external detectors after native/provider findings for `--input` scans only.
- Modify `src/lib.rs`: export the new module for tests.
- Modify `tests/integration.rs`: add fake TruffleHog fixtures and end-to-end CLI coverage.
- Modify `README.md`, `docs/cli.md`, `docs/detection.md`, `docs/security.md`, and `skills/redaction-cli/SKILL.md`: document the UX and trust boundary.

## Tasks

### Task 1: CLI Shape

- [ ] Add `DetectorArgs`, `DetectorSubcommand`, and `DetectorHelpTopic`.
- [ ] Add top-level `detector` command dispatch.
- [ ] Add scan flags `--detectors` and `--no-detectors`.
- [ ] Add parser tests for `detector install/use/current/list/verify/disable/default`.

### Task 2: External Detector State

- [ ] Create `src/external_detector.rs`.
- [ ] Add catalog entry `trufflehog/secrets-v1` with alias `trufflehog`.
- [ ] Store installed bundle metadata under `<data-root>/external-detectors/trufflehog/secrets-v1/bundle.state`.
- [ ] Store active detector targets under `<config-root>/active-detectors.state`.
- [ ] Store default mode under `<config-root>/external-detectors-default.state`.
- [ ] Implement `install`, `use`, `current`, `list`, `verify`, `disable`, and `default on/off`.

### Task 3: TruffleHog Adapter

- [ ] Resolve and hash the local `trufflehog` executable during install/verify.
- [ ] Run `trufflehog filesystem <path> --json --no-verification --no-update --no-color`.
- [ ] Parse newline-delimited JSON output using a small local parser for the fields we need.
- [ ] Extract `Raw` or `RawV2`, search for it in the scanned text, and emit `Finding` values with detector name `TRUFFLEHOG_SECRET`.
- [ ] Never include raw TruffleHog secret text in errors or reports.

### Task 4: Scan Integration

- [ ] In `main.rs`, determine whether external detectors should run from `--detectors`, `--no-detectors`, or persistent default.
- [ ] Apply external detectors only for `--input` file/directory scans.
- [ ] Make forced `--detectors` without `--input` a usage error.
- [ ] Merge external detector findings with native/provider findings before retain/except/redaction.
- [ ] In directory mode, record per-file errors and continue.

### Task 5: Tests and Docs

- [ ] Add integration tests with a fake `trufflehog` executable in `PATH`.
- [ ] Cover install/use/default/list/current/verify/disable.
- [ ] Cover `--detectors` redaction and default-on behavior.
- [ ] Cover `--no-detectors` override.
- [ ] Update README and docs with the exact commands, trust boundary, AGPL attribution, and no-network-verification default.
- [ ] Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --locked`, `cargo build --release --locked`, and `git diff --check`.
