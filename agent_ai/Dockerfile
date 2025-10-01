# Start from a lightweight Python image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY app.py .

# Create logs and outputs folders
RUN mkdir -p /app/logs /app/outputs

# Expose Flask port
EXPOSE 8000

# Run the app
CMD ["python3", "app.py"]

