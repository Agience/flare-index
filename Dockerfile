FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 flare
WORKDIR /work

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
        faiss-cpu==1.8.0 \
        cryptography==42.0.5 \
        numpy==1.26.4 \
        fastapi==0.110.0 \
        "uvicorn[standard]==0.29.0" \
        httpx==0.27.0 \
        pydantic==2.6.4 \
        pytest==8.1.1 \
        pytest-asyncio==0.23.6

# Phase 5: real-data benchmarks + showcase. CPU torch + sentence-transformers
# for real semantic embeddings. ~340MB additional, but enables genuine
# retrieval-quality numbers in the paper.
RUN pip install --no-cache-dir \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        torch==2.2.2+cpu \
    && pip install --no-cache-dir \
        sentence-transformers==2.7.0 \
        datasets==2.18.0

# Pre-download the embedding model into the image so showcase + bench
# work offline after build. ~80MB.
RUN python -c "from sentence_transformers import SentenceTransformer; \
    SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

COPY . .
RUN chown -R flare:flare /work
USER flare

ENV PYTHONPATH=/work
CMD ["pytest", "-q"]
