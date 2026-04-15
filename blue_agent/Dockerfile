FROM python:3.11-slim

WORKDIR /app

# System deps needed by some torch/transformers native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

# 1. Pin numpy<2 FIRST so pip can't resolve a newer one when installing torch
RUN pip install --no-cache-dir "numpy<2"

# 2. Install CPU-only PyTorch (avoids pulling the large CUDA variant)
RUN pip install --no-cache-dir \
        torch==2.2.2 \
        --index-url https://download.pytorch.org/whl/cpu

# 3. Install remaining Python dependencies
RUN pip install --no-cache-dir \
        flask==3.0.0 \
        requests==2.31.0 \
        unidecode==1.3.7 \
        pyyaml==6.0.1 \
        sentence-transformers==2.7.0

COPY . /app

# Pre-download the MiniLM model into the image so the container starts fast.
# The '|| true' means a build without internet still succeeds;
# the model will be downloaded on first container start instead.
ENV SBERT_MODEL=paraphrase-MiniLM-L6-v2
RUN python3 -c "\
from sentence_transformers import SentenceTransformer; \
SentenceTransformer('paraphrase-MiniLM-L6-v2'); \
print('[BLUE] Model pre-download complete.')" \
    || echo "[BLUE] Model pre-download skipped (no network at build time)."

ENV PYTHONUNBUFFERED=1

EXPOSE 8001

CMD ["python", "blue.py"]
