# Contributing

## Setup

```bash
python -m venv venv && source venv/bin/activate
make install-dev          # runtime + dev dependencies
make hooks                # install pre-commit hooks
cp .env.example .env      # optional: customize config
```

## Everyday commands

| Command | What it does |
|---------|--------------|
| `make dev` | Run the API with auto-reload on :8000 |
| `make demo` | Stream sample alerts through the pipeline |
| `make test` | Run the pytest suite with coverage |
| `make lint` / `make format` | Ruff check / autofix + format |
| `make docker-up` | Build and run via docker compose |

## Expectations

- `make lint` and `make test` must pass before a PR; CI runs both on
  Python 3.11 and 3.12.
- Add tests for new behavior — unit tests in `tests/unit`, API tests in
  `tests/integration`.
- Keep commits focused; use imperative subject lines
  (`Add syslog CEF parser`, not `updates`).
- No data, models, logs, or `.db` files in commits — pre-commit blocks
  files over 500 KB.
