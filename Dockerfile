# Base image
FROM python:3.11-slim

# Metadata
LABEL maintainer="matrix leons"
LABEL description="EvilWAF v2.4 - Transparent WAF Bypass Proxy"
LABEL version="2.4"

# Environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tor \
    curl \
    git \
    gcc \
    libssl-dev \
    libffi-dev \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directory for CA certificates
RUN mkdir -p /tmp/evilwaf_ca

# Tor configuration
RUN echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 0" >> /etc/tor/torrc

# Expose proxy port
EXPOSE 8080
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]