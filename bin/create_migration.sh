#!/bin/bash

# Create initial migration for new tables
echo "Creating initial migration for AbuseIPDB cache tables..."

# Generate migration
alembic revision --autogenerate -m "Add AbuseIPDB cache and API tracking tables"

echo "Migration created. Review the generated file and run 'alembic upgrade head' to apply."
