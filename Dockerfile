# Use an official Python image as the base
FROM python:3.10-slim

# Create a working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . /app/

# Create data directory
RUN mkdir -p /app/data

# Run the Flask app with Gunicorn in production with debug logging
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--log-level", "debug", "--capture-output", "--timeout", "300", "--keep-alive", "300", "app:create_app()"]
