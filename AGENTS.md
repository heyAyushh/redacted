# AGENTS.md

## Cursor Cloud specific instructions

This is a Rust binary project (`hello-rust`) using Cargo as its build system.

### Quick Reference

| Action | Command |
|--------|---------|
| Build | `cargo build` |
| Run | `cargo run` |
| Test | `cargo test` |
| Lint | `cargo clippy` |
| Format check | `cargo fmt --check` |
| Format fix | `cargo fmt` |

### Environment

- **Rust toolchain**: Installed via `rustup` at `/usr/local/cargo/bin/`. The `CARGO_HOME` and `RUSTUP_HOME` environment variables point there.
- **Components**: `clippy` and `rustfmt` are pre-installed.
- No external services, databases, or Docker containers are needed.
- The project compiles to a single binary; no dev server to keep running.
