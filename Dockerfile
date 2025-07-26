# Use an official Python image as the base
FROM python:3.10-slim

# Create a dedicated virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install system dependencies and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy only the application code
COPY app /app/app

# Create data directory
RUN mkdir -p /app/data

# Run the Flask app with Gunicorn in production with debug logging and extended timeout
CMD gunicorn --bind 0.0.0.0:5000 --log-level ${LOG_LEVEL:-info} --capture-output --timeout ${GUNICORN_TIMEOUT:-600} "app:create_app()"
