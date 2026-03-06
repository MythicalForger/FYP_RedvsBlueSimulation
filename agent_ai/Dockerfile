# Start from a lightweight Python image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all agent code (app + core + helpers)
COPY . .

# Create logs and outputs folders
RUN mkdir -p /app/logs /app/outputs

# Expose Flask’s port
EXPOSE 8000

# Start the Flask app
CMD ["python3", "app.py"]
