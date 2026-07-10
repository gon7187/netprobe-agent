## What changed

<!-- Describe the user-visible and internal changes. -->

## Why

<!-- Explain the diagnostic gap, bug, or maintenance need. -->

## Validation

- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run pyright src tests`
- [ ] `uv run pytest -q`

## Network-diagnostic safety

- [ ] Findings remain evidence-based and do not label a single timeout/RST as DPI.
- [ ] Route suggestions contain destination `/32` or `/128` only, never traceroute hops.
- [ ] Reports and fixtures contain no credentials, tokens, or private endpoints.
