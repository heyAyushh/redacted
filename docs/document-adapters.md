# Document Adapters

This document describes the optional document adapter subsystem behind
`redacted --document-adapter`.

## Scope

- Document adapters are **off by default**.
- Native text scanning still runs exactly as before.
- Document adapters are a preprocessing step for supported non-text files.
- The document-adapter path is an **adapter boundary** outside the hardened
  Rust-only core scan path.
- `redacted` still owns masking, reports, retain rules, except rules, and file
  writes.
- Document adapter registry entries include source, license, distribution,
  bundled, and network-default metadata. See
  [`extension-licenses.md`](extension-licenses.md).

## Alias Resolution

`redacted` supports two selector forms:

- Aliases: `pdf`, `firecrawl-pdf`
- Exact targets: `poppler/pdftotext-v1`, `firecrawl/pdf-inspector-v1`

Aliases are onboarding shortcuts. They resolve to pinned exact targets.
For document types, the short alias should stay human-sized. The exact target
names the current adapter implementation.

Current built-in mapping:

- `pdf -> poppler/pdftotext-v1`
- `firecrawl-pdf -> firecrawl/pdf-inspector-v1`

## Commands

```bash
redacted document enable <adapter-or-target>
redacted document install <adapter-or-target>
redacted document use <adapter-or-target>
redacted document current
redacted document list
redacted document verify [<adapter-or-target> | --all]
redacted document disable
```

Human-friendly setup:

```bash
redacted document enable pdf
redacted --input report.pdf --document-adapter
```

Firecrawl PDF Inspector setup:

```bash
redacted document enable firecrawl-pdf
redacted --input report.pdf --document-adapter
```

## Runtime and Support

Current v1 adapter targets:

- `poppler/pdftotext-v1`
- `firecrawl/pdf-inspector-v1`
- Adapter runtimes: local `pdftotext` command or local Firecrawl `pdf2md` command
- Distribution: external binary, not vendored into the MIT core
- Supported input extensions in v1: `.pdf`

If `pdftotext` or `pdf2md` is unavailable for the selected adapter, install
fails fast with the next command to run.

## State and Install Layout

Config state:

- `XDG_CONFIG_HOME/redacted` when `XDG_CONFIG_HOME` is set
- otherwise `~/.config/redacted`

Data state:

- `XDG_DATA_HOME/redacted` when `XDG_DATA_HOME` is set
- otherwise `~/.local/share/redacted`

Override variables:

- `REDACTED_CONFIG_HOME`
- `REDACTED_DATA_HOME`

Important files:

- Active adapter: `active-document-adapter.state`
- Installed bundles: `document-adapters/<provider>/<model>/...`

Example bundle layout:

```text
<data-root>/document-adapters/poppler/pdftotext-v1/
  bundle.state
  verified.state
  runner/
    pdftotext_runner.py

<data-root>/document-adapters/firecrawl/pdf-inspector-v1/
  bundle.state
  verified.state
  runner/
    firecrawl_pdf_inspector_runner.py
```

## Integrity Verification

`redacted document install ...`:

1. resolves selector to exact target
2. installs adapter runner bundle
3. verifies runner integrity against the pinned script
4. verifies local runtime prerequisite (`pdftotext`)
5. writes `verified.state`

`redacted document verify ...` re-runs those checks and refreshes
`verified.state`.

Scans with `--document-adapter` do **not** install or auto-switch adapters.

## Scan Behavior

When `--document-adapter` is enabled for a supported document file:

1. adapter extracts text from the file
2. core detector pipeline runs on extracted text
3. findings merge and policy logic runs as usual
4. output/report logic follows existing `redacted` behavior

`--in-place` is blocked for document-adapter extracted files because source files
are non-text documents.

## Runner Contract

The current v1 runner is invoked as:

```bash
<runner> --target <exact-target> --input <absolute-or-relative-path>
```

Runner rules:

- input path must be a single document file
- extracted UTF-8 text is written to stdout
- non-zero exit indicates extraction failure

Future adapter targets can provide different runtimes behind the same command
shape.

## Troubleshooting

- No active adapter:
  - `redacted document enable pdf`
- Need to see install state:
  - `redacted document list`
- Bundle installed but not active:
  - `redacted document use pdf`
- Want Firecrawl PDF Inspector:
  - install `pdf2md`, then run `redacted document enable firecrawl-pdf`
- Missing local runtime:
  - install `pdftotext`, then run `redacted document verify pdf`
- Clear current adapter:
  - `redacted document disable`
