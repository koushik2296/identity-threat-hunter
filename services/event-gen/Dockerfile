FROM python:3.11-slim
WORKDIR /app
COPY app/ /app/app/
RUN pip install --no-cache-dir fastapi uvicorn requests
ENV PORT=8080
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
