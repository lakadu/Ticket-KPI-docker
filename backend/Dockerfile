FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (build-essential untuk bcrypt/reportlab, curl untuk healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python deps dulu (layer caching)
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy source
COPY . ./

EXPOSE 8001

# Production runtime — 2 workers, tanpa --reload
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips=*"]
