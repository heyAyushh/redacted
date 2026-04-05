# AGENTS.md

## Cursor Cloud specific instructions

This is a production-grade Rust CLI tool (`redacted`) for redacting secrets and PII from text and files. Zero external dependencies — only `std`.

### Quick Reference

| Action | Command |
|--------|---------|
| Build | `cargo build` |
| Run | `cargo run -- --help` |
| Test | `cargo test` |
| Lint | `cargo clippy` |
| Format check | `cargo fmt --check` |
| Format fix | `cargo fmt` |

### Environment

- **Rust toolchain**: Pre-installed via `rustup`. Components `clippy` and `rustfmt` are available.
- **Zero external dependencies**: No crates.io deps. No network, Docker, or databases needed.
- **Single binary**: Compiles to `target/debug/redacted` (or `target/release/redacted`).
- See `skills/redaction-cli/SKILL.md` for code structure and development conventions.
- See `docs/` for full documentation including threat model and security guarantees.

### Key Gotchas

- No subcommand — use `cargo run -- --text "..."` directly, not `cargo run -- redact --text "..."`.
- IPv4 and IPv6 share the same detector name `IP` → marker is `[REDACTED:IP]`.
- Filesystem paths (absolute, relative, ~, Windows) are detected → `[REDACTED:PATH]`.
- The custom pattern matcher is intentionally limited (no backreferences, bounded repetition) to prevent ReDoS.
- Reports always mask matched values; never log full secret strings.
- Atomic writes use temp files in the same directory as the target; ensure the directory is writable.
