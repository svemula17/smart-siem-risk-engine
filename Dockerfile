FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin siem
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY app/ app/
COPY scripts/ scripts/
COPY rules/ rules/
COPY run.py .
COPY data/samples/ data/samples/
COPY data/blocklist.json data/blocklist.json

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////app/data/smart_siem.db

RUN chown -R siem:siem /app
USER siem

VOLUME /app/data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
