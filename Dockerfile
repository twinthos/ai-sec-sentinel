FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_sec_sentinel.py .
COPY news_scanner.py .
COPY sentinel_config.json .
COPY plugins/ plugins/

RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

VOLUME ["/data"]

ENTRYPOINT ["python3", "/app/ai_sec_sentinel.py"]
CMD ["--help"]
