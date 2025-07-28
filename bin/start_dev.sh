#!/bin/bash

# Start development server
echo "Starting AbuseIPDB IOC Management System..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please create .env file from .env.example"
    exit 1
fi

# Run migrations
echo "Checking database migrations..."
alembic upgrade head

# Start the application
echo "Starting FastAPI application..."
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
