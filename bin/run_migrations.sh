#!/bin/bash

# Run database migrations
echo "Running database migrations..."

# Check if .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please create .env file from .env.example"
    exit 1
fi

# Run migrations
alembic upgrade head

echo "Migrations completed."
