FROM python:3.11-slim

WORKDIR /app

# System dependencies (pdftotext pour le RAG)
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code source
COPY . .

# Dossiers persistants (montés en volume)
RUN mkdir -p rag/vectors rag/docs

EXPOSE 5000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "120", "--log-level", "info", "app:app"]
