# AGENTS.md

## Cursor Cloud specific instructions

This is a production-grade Rust CLI tool (`redact`) for redacting secrets and PII from text and files. Zero external dependencies — only `std`.

### Quick Reference

| Action | Command |
|--------|---------|
| Build | `cargo build` |
| Run | `cargo run -- redact --help` |
| Test | `cargo test` |
| Lint | `cargo clippy` |
| Format check | `cargo fmt --check` |
| Format fix | `cargo fmt` |

### Environment

- **Rust toolchain**: Pre-installed via `rustup`. Components `clippy` and `rustfmt` are available.
- **Zero external dependencies**: No crates.io deps. No network, Docker, or databases needed.
- **Single binary**: Compiles to `target/debug/redact` (or `target/release/redact`).
- See `skills/redaction-cli/SKILL.md` for code structure and development conventions.
- See `docs/` for full documentation including threat model and security guarantees.

### Key Gotchas

- The CLI uses a `redact` subcommand: `cargo run -- redact --text "..."`, not `cargo run -- --text "..."`.
- The custom pattern matcher is intentionally limited (no backreferences, bounded repetition) to prevent ReDoS.
- Reports always mask matched values; never log full secret strings.
- Atomic writes use temp files in the same directory as the target; ensure the directory is writable.
