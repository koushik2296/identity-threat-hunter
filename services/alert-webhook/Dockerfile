FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV PORT=8080
CMD exec gunicorn -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT --timeout 120
