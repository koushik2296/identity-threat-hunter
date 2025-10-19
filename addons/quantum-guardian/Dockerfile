# Quantum Guardian
FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app

# EXPOSE is optional for Cloud Run; 
# EXPOSE 8080

ENV PYTHONUNBUFFERED=1

# IMPORTANT: bind to the port Cloud Run provides
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
