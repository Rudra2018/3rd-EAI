FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y     gcc     g++     libffi-dev     libssl-dev     && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements-enhanced.txt .
RUN pip install --no-cache-dir -r requirements-enhanced.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p artifacts logs models nvd_cache uploads reports data

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3     CMD curl -f http://localhost:4000/api/status || exit 1

# Run application
CMD ["python", "enhanced_app.py"]
