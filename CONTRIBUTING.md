# Contributing

Thanks for improving `netprobe-agent`.

## Setup

```bash
uv sync --extra dev
uv run pre-commit install
```

## Local gate

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright src tests
uv run pytest -q
```

Unit tests must be deterministic and must not access the public network. Put
real-network checks behind the `integration` marker and keep them opt-in.

## Diagnostic rules

- Do not classify a single timeout, reset, DNS mismatch, or traceroute gap as DPI.
- Prefer exact endpoint comparisons and reproducibility across direct/VPN paths.
- Keep insecure TLS probes explicitly diagnostic; never send credentials through them.
- Generate only exact destination `/32` and `/128` routes. Never route traceroute hops.
- Bound response sizes, parser work, subprocess duration, and address counts.

Open a focused pull request and include the commands used to validate it.
