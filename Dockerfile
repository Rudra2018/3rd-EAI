FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Set environment variables
ENV PORT=8080
ENV PYTHONPATH=/app

# CRITICAL: Expose the port and bind to 0.0.0.0
EXPOSE 8080

# Default to program_fetcher, but allow override via deployment
CMD exec uvicorn api_scanner.services.program_fetcher:app --host 0.0.0.0 --port $PORT

