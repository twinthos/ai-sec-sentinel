FROM python:3.11-slim

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Create data directory with proper permissions
RUN mkdir -p /data && chown -R sentinel:sentinel /data /app
VOLUME ["/data"]

# Switch to non-root user
USER sentinel

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SENTINEL_DATA_DIR=/data
CMD ["python3", "ai_sec_sentinel.py", "--daemon", "--interval", "60"]
