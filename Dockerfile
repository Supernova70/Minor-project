FROM python:3.12-bookworm

WORKDIR /app

# System dependencies:
#   libmagic1  — required by python-magic for real MIME-type detection
#   file       — the `file` CLI utility (uses libmagic internally)
#   yara-python compiles its bundled YARA C source using gcc (already in image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    file \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file first (Docker layer caching)
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# Copy application code
COPY . .

# Create directories
RUN mkdir -p /app/uploads /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
