# Use a slim Python 3.11 image as the base.
FROM python:3.11-slim

# Set environment variables to optimize Python's performance in a container.
# PYTHONUNBUFFERED ensures logs are streamed to the console in real-time.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set the working directory inside the container to /app.
# All subsequent commands will run from this directory.
WORKDIR /app

# Copy the requirements file into the container.
# This allows pip to install dependencies before the rest of the code is copied,
# which optimizes Docker's layer caching.
COPY requirements.txt .

# Install the Python dependencies.
# The --no-cache-dir flag reduces the image size by not storing the pip cache.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project from the local directory into the /app directory in the container.
COPY . .

# The `start.sh` script is the main entrypoint for the application.
# It handles diagnostics and then starts the Uvicorn server.
CMD ["/bin/sh", "start.sh"]
