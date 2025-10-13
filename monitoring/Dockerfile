FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    useradd -ms /bin/bash appuser

COPY . .

# Create directories as root, then change ownership
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 9000

# Start the API (log watcher will be started separately)
CMD ["python", "stats_api.py"]
