FROM python:3.11-slim

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the service source code
COPY . .

# Cloud Run will inject $PORT; default 8080 for local sanity
ENV PORT=8080

# Start FastAPI via module form (avoids PATH issues with uvicorn)
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]