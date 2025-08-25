#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Rudra's Third Eye AI - Initialization Script
Sets up databases, downloads initial data, and prepares the environment
"""

import os
import sys
import json
import sqlite3
import asyncio
import logging
from pathlib import Path
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('initialization.log'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

def create_directories():
    """Create necessary directories"""
    directories = [
        'artifacts',
        'logs', 
        'models',
        'nvd_cache',
        'uploads',
        'reports',
        'data',
        'backup'
    ]
    
    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        log.info(f"✅ Created directory: {directory}")

def initialize_databases():
    """Initialize SQLite databases"""
    
    # Main application database
    main_db_path = 'data/rudra_enhanced.db'
    conn = sqlite3.connect(main_db_path)
    cursor = conn.cursor()
    
    # Create scan results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            target_url TEXT,
            scan_type TEXT,
            status TEXT,
            progress INTEGER DEFAULT 0,
            vulnerabilities_count INTEGER DEFAULT 0,
            results_json TEXT,
            ai_insights TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create learning data table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS learning_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            features TEXT,
            labels TEXT,
            confidence REAL,
            timestamp TEXT,
            model_version TEXT,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id)
        )
    ''')
    
    # Create AI model performance table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT,
            accuracy REAL,
            precision_score REAL,
            recall REAL,
            f1_score REAL,
            timestamp TEXT,
            metadata TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    log.info(f"✅ Initialized main database: {main_db_path}")

def create_default_config():
    """Create default configuration files"""
    
    # Enhanced configuration
    config = {
        "app": {
            "name": "Rudra's Third Eye AI - Enhanced",
            "version": "3.0.0",
            "debug": False,
            "port": 4000
        },
        "ai": {
            "models": {
                "primary": {
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "temperature": 0.3,
                    "max_tokens": 4000
                },
                "fallback": {
                    "provider": "gemini",
                    "model": "gemini-2.5-flash",
                    "temperature": 0.3,
                    "max_tokens": 4000
                }
            },
            "crewai": {
                "enabled": True,
                "default_crew": "comprehensive",
                "max_execution_time": 1800
            }
        },
        "learning": {
            "online_learning": True,
            "adaptation_threshold": 0.1,
            "min_samples_for_update": 50,
            "model_retention_days": 30,
            "concept_drift_detection": True
        },
        "intelligence": {
            "nvd": {
                "enabled": True,
                "sync_interval_hours": 6,
                "severity_filter": ["CRITICAL", "HIGH", "MEDIUM"]
            },
            "hackerone": {
                "enabled": True,
                "disclosed_only": True
            }
        },
        "scanning": {
            "concurrent_scans": 3,
            "max_scan_duration_minutes": 60,
            "rate_limit_per_second": 10,
            "timeout_seconds": 30
        },
        "reporting": {
            "generate_pdf": True,
            "include_ai_analysis": True,
            "compliance_frameworks": ["NIST", "OWASP"],
            "max_report_age_days": 90
        }
    }
    
    config_path = 'config/enhanced_config.json'
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    log.info(f"✅ Created default configuration: {config_path}")

def create_env_template():
    """Create .env template file"""
    
    env_template = """# Enhanced Rudra's Third Eye AI Environment Configuration

# AI Model APIs (at least one required)
OPENAI_API_KEY=your-openai-api-key-here
GEMINI_API_KEY=your-gemini-api-key-here  
ANTHROPIC_API_KEY=your-claude-api-key-here

# Vulnerability Intelligence APIs
NVD_API_KEY=your-nvd-api-key-here
HACKERONE_API_USERNAME=your-hackerone-username
HACKERONE_API_TOKEN=your-hackerone-api-token

# Database Configuration  
DATABASE_URL=sqlite:///./data/rudra_enhanced.db
REDIS_URL=redis://localhost:6379


# External Integrations
SLACK_WEBHOOK_URL=your-slack-webhook-for-notifications
DISCORD_WEBHOOK_URL=your-discord-webhook-for-notifications

# Monitoring & Analytics
SENTRY_DSN=your-sentry-dsn-for-error-tracking
PROMETHEUS_ENABLED=true

# Development Settings
DEBUG=false
FLASK_ENV=production
LOG_LEVEL=INFO

# Performance Tuning
MAX_WORKERS=4
CACHE_TTL=3600
REQUEST_TIMEOUT=30

# Feature Flags
AI_ENHANCED=true
ZERO_DAY_DETECTION=true
CONTINUOUS_LEARNING=true
REAL_TIME_INTEL=true
"""
    
    env_path = '.env.template'
    with open(env_path, 'w') as f:
        f.write(env_template)
    
    log.info(f"✅ Created environment template: {env_path}")
    log.warning("⚠️  Please copy .env.template to .env and configure your API keys")

async def download_initial_data():
    """Download initial vulnerability data"""
    try:
        log.info("🔄 Downloading initial vulnerability data...")
        
        # This would typically sync with NVD, but for initialization we'll create sample data
        sample_cves = [
            {
                "cve_id": "CVE-2024-SAMPLE-001",
                "description": "Sample API authentication bypass vulnerability",
                "cvss_score": 9.1,
                "severity": "CRITICAL",
                "published": datetime.now().isoformat(),
                "cwe_ids": ["CWE-287"],
                "attack_vector": "NETWORK"
            },
            {
                "cve_id": "CVE-2024-SAMPLE-002", 
                "description": "Sample SQL injection in API parameter",
                "cvss_score": 8.2,
                "severity": "HIGH",
                "published": datetime.now().isoformat(),
                "cwe_ids": ["CWE-89"],
                "attack_vector": "NETWORK"
            }
        ]
        
        # Save sample data
        sample_data_path = 'data/initial_vulnerabilities.json'
        with open(sample_data_path, 'w') as f:
            json.dump(sample_cves, f, indent=2)
        
        log.info(f"✅ Created sample vulnerability data: {sample_data_path}")
        
    except Exception as e:
        log.error(f"❌ Failed to download initial data: {e}")

def initialize_ml_models():
    """Initialize basic ML models"""
    try:
        log.info("🧠 Initializing ML models...")
        
        # Create model metadata
        model_metadata = {
            "anomaly_detector": {
                "type": "IsolationForest",
                "version": "1.0.0",
                "created": datetime.now().isoformat(),
                "parameters": {
                    "contamination": 0.1,
                    "n_estimators": 100
                }
            },
            "vulnerability_classifier": {
                "type": "RandomForestClassifier",
                "version": "1.0.0", 
                "created": datetime.now().isoformat(),
                "parameters": {
                    "n_estimators": 200,
                    "max_depth": 10
                }
            }
        }
        
        metadata_path = 'models/model_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(model_metadata, f, indent=2)
        
        log.info(f"✅ Created ML model metadata: {metadata_path}")
        
    except Exception as e:
        log.error(f"❌ Failed to initialize ML models: {e}")

def create_docker_files():
    """Create Docker configuration files"""
    
    # Dockerfile
    dockerfile_content = """FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

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
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:4000/api/status || exit 1

# Run application
CMD ["python", "enhanced_app.py"]
"""
    
    with open('Dockerfile', 'w') as f:
        f.write(dockerfile_content)
    
    # Docker Compose
    compose_content = """version: '3.8'

services:
  rudra-enhanced:
    build: .
    ports:
      - "4000:4000"
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=sqlite:///./data/rudra_enhanced.db
    volumes:
      - ./data:/app/data
      - ./artifacts:/app/artifacts
      - ./logs:/app/logs
      - ./models:/app/models
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:4000
    depends_on:
      - rudra-enhanced
    restart: unless-stopped

volumes:
  redis_data:
"""
    
    with open('docker-compose.yml', 'w') as f:
        f.write(compose_content)
    
    log.info("✅ Created Docker configuration files")

def create_scripts():
    """Create utility scripts"""
    
    # Start script
    start_script = """#!/bin/bash
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
"""
    
    os.makedirs('scripts', exist_ok=True)
    with open('scripts/start.sh', 'w') as f:
        f.write(start_script)
    os.chmod('scripts/start.sh', 0o755)
    
    # Test script
    test_script = """#!/usr/bin/env python3
# Enhanced Rudra's Third Eye AI - Test Script

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_ai_models():
    '''Test AI model connectivity'''
    print("🤖 Testing AI Models...")
    
    try:
        from ai.advanced_ai_coordinator import AdvancedAICoordinator
        coordinator = AdvancedAICoordinator()
        
        models = coordinator.models
        print(f"✅ Available AI models: {list(models.keys())}")
        
        return True
    except Exception as e:
        print(f"❌ AI models test failed: {e}")
        return False

def test_databases():
    '''Test database connectivity'''
    print("🗄️ Testing Databases...")
    
    try:
        import sqlite3
        conn = sqlite3.connect('data/rudra_enhanced.db')
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        print("✅ Database connection successful")
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_ml_libraries():
    '''Test ML library imports'''
    print("🧠 Testing ML Libraries...")
    
    try:
        import sklearn
        import numpy
        import pandas
        print("✅ Core ML libraries available")
        
        try:
            import torch
            print("✅ PyTorch available")
        except ImportError:
            print("⚠️  PyTorch not available (optional)")
            
        return True
    except Exception as e:
        print(f"❌ ML libraries test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Running Enhanced Rudra Tests...")
    
    tests = [
        test_databases,
        test_ml_libraries, 
        test_ai_models
    ]
    
    results = []
    for test in tests:
        results.append(test())
        print()
    
    if all(results):
        print("✅ All tests passed! Enhanced Rudra is ready.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the configuration.")
        sys.exit(1)
"""
    
    with open('scripts/test_enhanced.py', 'w') as f:
        f.write(test_script)
    os.chmod('scripts/test_enhanced.py', 0o755)
    
    log.info("✅ Created utility scripts")

def main():
    """Main initialization function"""
    
    log.info("🚀 Initializing Enhanced Rudra's Third Eye AI...")
    
    try:
        # Create directory structure
        create_directories()
        
        # Initialize databases
        initialize_databases()
        
        # Create configuration files
        create_default_config()
        create_env_template()
        
        # Download initial data
        asyncio.run(download_initial_data())
        
        # Initialize ML components
        initialize_ml_models()
        
        # Create Docker files
        create_docker_files()
        
        # Create utility scripts
        create_scripts()
        
        log.info("✅ Enhanced Rudra's Third Eye AI initialization completed!")
        
        print("\n" + "="*60)
        print("🎉 INITIALIZATION COMPLETED SUCCESSFULLY!")
        print("="*60)
        print()
        print("Next steps:")
        print("1. Copy .env.template to .env and configure your API keys")
        print("2. Run 'python scripts/test_enhanced.py' to verify setup")
        print("3. Start the application with 'python enhanced_app.py'")
        print("4. Access the dashboard at http://localhost:4000")
        print()
        print("For detailed setup instructions, see enhanced-readme.md")
        print("="*60)
        
    except Exception as e:
        log.error(f"❌ Initialization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
