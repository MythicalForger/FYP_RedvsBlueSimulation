FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy benchmark scripts
COPY . .

# Create results directory
RUN mkdir -p /app/results /app/logs

# Default command (can be overridden)
CMD ["python", "benchmark_runner.py", "--help"]