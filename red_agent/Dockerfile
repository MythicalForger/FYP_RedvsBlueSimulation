FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY red.py .

CMD ["python3", "red.py"]

COPY attacks.json /app/attacks.json
