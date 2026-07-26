FROM python:3.11-slim
 
# libgomp1 is required by lightgbm's compiled backend
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*
 
WORKDIR /app
 
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
# Copy the whole project (respects .dockerignore below)
COPY . .
 
# Bake the demo dataset into the image at build time if it doesn't already
# exist in the repo, so the container never needs network/file writes at
# runtime to produce it. Safe to skip if data/sample_logs.csv is already
# committed.
RUN if [ ! -f data/sample_logs.csv ]; then \
      python data/generate_logs.py --out data/sample_logs.csv; \
    fi
 
# Render injects $PORT at runtime; must bind to it, not a hardcoded port.
# main.py uses relative imports (from .db.init_db import ...), so it must
# run as the "api" package from the project root — not `cd api && uvicorn main:app`.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
 













