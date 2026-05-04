# Extension Licenses

`redacted` keeps the core CLI separate from optional extensions.

The core binary is MIT licensed, Rust standard-library only, and does not call
external tools or download models during the default scan path. Optional
providers, document adapters, and external detectors must declare their own
license and distribution metadata in their registry entry.

## Required Registry Metadata

Every optional extension registry entry must include:

| Field | Meaning |
|-------|---------|
| `target` | Exact target name, such as `openai/privacy-filter-v1` |
| `kind` | `provider`, `detector`, or `document` |
| `source_url` | Upstream source, model, tool, or project URL |
| `license` | SPDX-style license string when known |
| `distribution` | `external-binary`, `downloaded-artifact`, `vendored-source`, or `linked-library` |
| `bundled` | Whether the upstream code/artifact ships inside the `redacted` repository or binary |
| `network_default` | Whether install or normal operation uses network by default |
| `notice` | Short human-facing notice shown before install/use for non-MIT or unknown-license extensions |

The metadata is shown by:

```bash
redacted provider list
redacted detector list
redacted document list
```

## Policy

- The core `redacted` CLI remains MIT licensed.
- External binaries do not change the core license because they are invoked as
  separate user-installed tools.
- Downloaded artifacts must have pinned URLs, sizes, hashes, license metadata,
  and an install/use notice.
- Vendored source and linked libraries require explicit maintainer approval
  before integration.
- Unknown-license extensions must not be enabled by default.
- Scans must never download, auto-update, or auto-switch extensions.
- Non-MIT and unknown-license extensions must print a notice during install/use.

## Current Extensions

| Target | Kind | Source | License | Distribution | Bundled | Network default |
|--------|------|--------|---------|--------------|---------|-----------------|
| `openai/privacy-filter-v1` | provider | [OpenAI Privacy Filter source](https://github.com/openai/privacy-filter/tree/2e8c95b9771eec29ef61012f6e5e836f9bad7635) and [model artifacts](https://huggingface.co/openai/privacy-filter/tree/main/original) | Apache-2.0 | downloaded-artifact | no | yes |
| `openai/privacy-filter-v1-mlx` | provider | [mlx-community/openai-privacy-filter-4bit](https://huggingface.co/mlx-community/openai-privacy-filter-4bit/tree/8b784df48dd38a36b757f50c73d23e5bd38f3db0) | Apache-2.0 | downloaded-artifact | no | yes |
| `trufflehog/secrets-v1` | detector | [TruffleHog](https://github.com/trufflesecurity/trufflehog/tree/main) | AGPL-3.0 | external-binary | no | no |
| `poppler/pdftotext-v1` | document | [Poppler pdftotext](https://poppler.freedesktop.org/) | GPL-2.0-or-later | external-binary | no | no |

## Reserved Extension Names

Firecrawl PDF Inspector should use a separate future target such as
`firecrawl/pdf-inspector-v1`. Do not use `pdf-inspector` for the Poppler
adapter; `pdf` is the human alias for the currently active PDF document type,
and the exact target names the selected adapter implementation.

## Contribution Checklist

Before adding a provider, detector, or document adapter:

- Add registry metadata for target, kind, source URL, license, distribution,
  bundled, network default, and notice text.
- Add the extension to `docs/extension-licenses.md` and README attribution.
- If distribution is `downloaded-artifact`, pin every URL, byte size, and SHA-256.
- If distribution is `external-binary`, do not vendor or link the upstream code.
- If distribution is `vendored-source` or `linked-library`, get maintainer
  approval before merging.
- If license is unknown, keep the extension disabled by default and document the
  missing license.
- Add tests that `list` output shows license metadata and install/use prints the
  required notice.
