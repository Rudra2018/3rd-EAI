#!/bin/bash
# Enhanced Rudra's Third Eye AI - Start Script

echo "🚀 Starting Enhanced Rudra's Third Eye AI..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade dependencies
echo "Installing dependencies..."
pip install -r requirements-enhanced.txt

# Check configuration
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Please copy .env.template to .env and configure your API keys."
    exit 1
fi

# Initialize if needed
if [ ! -f "data/rudra_enhanced.db" ]; then
    echo "Initializing database and models..."
    python scripts/initialize_enhanced.py
fi

# Start the application
echo "Starting enhanced application..."
python enhanced_app.py
