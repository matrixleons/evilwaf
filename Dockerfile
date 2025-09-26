FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p output scan_results payloads/generated

# Make scripts executable
RUN chmod +x evilwaf.py

# Create non-root user
RUN groupadd -r evilwaf && useradd -r -g evilwaf evilwaf
RUN chown -R evilwaf:evilwaf /app
USER evilwaf

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080', timeout=2)" || exit 1

# Default command
CMD ["python", "evilwaf.py", "--help"]
