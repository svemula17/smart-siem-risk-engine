.PHONY: install install-dev dev run seed demo test lint format docker-build docker-up docker-down train hooks

install:
	pip install -r requirements.txt

install-dev: install
	pip install -r requirements-dev.txt

dev:
	uvicorn app.main:app --reload --port 8000

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

seed:
	python -m app.ingestion.sample_generator

demo:
	python run.py

test:
	pytest

lint:
	ruff check .

format:
	ruff check --fix . && ruff format .

docker-build:
	docker build -t smart-siem .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

train:
	python scripts/train_ml_model.py

hooks:
	pre-commit install
