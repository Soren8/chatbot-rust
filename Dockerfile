# Use an official Python image as the base
FROM python:3.10-slim

# Create a working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . /app/

# Run the Flask app with Gunicorn in production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:create_app()"]
