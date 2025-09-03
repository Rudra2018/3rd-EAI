# api_scanner/Dockerfile
# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    APP_MODULE=api_scanner.server.main:app

WORKDIR /app

# Install deps for this subfolder context
# (This refers to api_scanner/requirements.txt because build context is api_scanner/)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir uvicorn[standard]

# Copy the rest of the subfolder
COPY . .

# Bind to 0.0.0.0:$PORT and rely on APP_MODULE (override-able at deploy time)
CMD ["bash", "-lc", "exec uvicorn ${APP_MODULE} --host 0.0.0.0 --port ${PORT}"]

