"""
Adaptive Security Suite - Chapter 3 Implementation
Complete software-based cybersecurity solution with AI/ML capabilities
Integrates all four architectural layers: Telemetry, Analytics, Policy, Enforcement
"""

import os
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, jsonify, request, render_template_string, make_response, send_from_directory, abort

from typing import Optional, List, Dict, Any
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

# Original application modules
from app.auth import auth_blueprint
from app.utils import require_auth
from app.encryption import encryption_blueprint
from app.threat_detection import threat_blueprint
from app.adaptive_engine import adaptive_blueprint
from config.security_config import API_SECURITY, SESSION_CONFIG
from models import db, init_database, BlacklistedToken

# New security features (Phase 1)
from app.mfa import mfa_blueprint
from app.device_fingerprinting import device_blueprint
from app.key_management import kms_blueprint

# Chapter 3 Adaptive Security Suite
from app.adaptive_security_suite import (
    AdaptiveSecuritySuite, AdaptiveSecurityConfig, create_default_suite
)

# Alert System
from app.alert_system import get_alert_system
from app.data_ingest import load_network_devices, load_threat_events

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Global suite instance
adaptive_suite = None
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "static" / "dist"

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global adaptive_suite

    logger.info(f"Received signal {signum}, shutting down...")

    if adaptive_suite:
        adaptive_suite.stop_suite()

def persist_external_threats() -> None:
    """Persist external threat events to disk."""
    with data_lock:
        THREAT_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not app.external_threat_events:
            if THREAT_DATA_FILE.exists():
                THREAT_DATA_FILE.unlink()
            return
        with THREAT_DATA_FILE.open('w', encoding='utf-8') as handle:
            for event in app.external_threat_events:
                handle.write(json.dumps(event, default=str) + '\n')


def persist_external_devices() -> None:
    """Persist external network device inventory to disk."""
    with data_lock:
        DEVICE_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with DEVICE_DATA_FILE.open('w', encoding='utf-8') as handle:
            json.dump(app.external_network_devices, handle, default=str, indent=2)

        # Save suite state before shutdown
        try:
            os.makedirs('data/suite_state', exist_ok=True)
            adaptive_suite.save_suite_state('data/suite_state')
        except Exception as e:
            logger.error(f"Failed to save suite state: {e}")

    sys.exit(0)

app = Flask(__name__)

DATA_DIR = Path(os.getenv('DATA_DIR', 'data'))
DATA_DIR.mkdir(parents=True, exist_ok=True)
THREAT_DATA_FILE = Path(os.getenv('THREAT_DATA_FILE', DATA_DIR / 'threat_events.jsonl'))
DEVICE_DATA_FILE = Path(os.getenv('DEVICE_DATA_FILE', DATA_DIR / 'network_devices.json'))

data_lock = threading.Lock()
app.external_threat_events = []
app.external_network_devices = []

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def _parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.min
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    return datetime.min




def load_external_data() -> None:
    """Load threat and device data from disk."""
    with data_lock:
        app.external_threat_events = load_threat_events(THREAT_DATA_FILE) if THREAT_DATA_FILE.exists() else []
        app.external_network_devices = load_network_devices(DEVICE_DATA_FILE) if DEVICE_DATA_FILE.exists() else []
    logger.info(
        "Loaded %d external threat events and %d network devices",
        len(app.external_threat_events),
        len(app.external_network_devices),
    )


def persist_external_threats() -> None:
    """Persist external threat events to disk."""
    with data_lock:
        THREAT_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not app.external_threat_events:
            if THREAT_DATA_FILE.exists():
                THREAT_DATA_FILE.unlink()
            return
        with THREAT_DATA_FILE.open('w', encoding='utf-8') as handle:
            for event in app.external_threat_events:
                handle.write(json.dumps(event, default=str) + '\n')


def persist_external_devices() -> None:
    """Persist external network device inventory to disk."""
    with data_lock:
        DEVICE_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with DEVICE_DATA_FILE.open('w', encoding='utf-8') as handle:
            json.dump(app.external_network_devices, handle, default=str, indent=2)

