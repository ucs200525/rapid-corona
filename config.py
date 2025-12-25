"""
Configuration file for DDoS Mitigation System
"""

import os
import platform

# System Configuration
PLATFORM = platform.system().lower()  # 'linux' or 'windows'
DEBUG_MODE = os.getenv('DEBUG', 'False').lower() == 'true'

# Network Configuration
DEFAULT_INTERFACE = 'eth0' if PLATFORM == 'linux' else 'Ethernet'
NETWORK_INTERFACE = os.getenv('INTERFACE', DEFAULT_INTERFACE)

# eBPF Configuration
EBPF_PROGRAM_PATH = 'src/ebpf/xdp_filter.c'  # BCC compiles from C source
XDP_MODE = 'native'  # Options: 'native', 'generic', 'offload'

# Detection Thresholds
class DetectionThresholds:
    # Packet rate thresholds (packets per second)
    # NOTE: Lowered for testing - increase in production
    NORMAL_PPS_BASELINE = 100   # Expected normal traffic
    ALERT_PPS_THRESHOLD = 500   # Alert threshold (was 100000)
    ATTACK_PPS_THRESHOLD = 2000 # Definite attack threshold (was 500000)
    
    # Statistical thresholds
    SIGMA_MULTIPLIER = 2.0  # Standard deviation multiplier for anomaly (was 3.5)
    MIN_ENTROPY = 3.0  # Minimum source IP entropy (lower = more concentrated)
    
    # Rate of change detection
    MAX_CHANGE_RATE = 3.0  # Max allowed rate increase (3x, was 5x)
    
    # Protocol distribution (approximate normal ratios)
    NORMAL_TCP_RATIO = 0.85  # 85% TCP
    NORMAL_UDP_RATIO = 0.10  # 10% UDP
    NORMAL_ICMP_RATIO = 0.05  # 5% ICMP
    PROTOCOL_DEVIATION_THRESHOLD = 0.3  # 30% deviation is suspicious

# Time Window Configuration
class TimeWindows:
    BASELINE_WINDOW = 300  # 5 minutes for baseline calculation
    DETECTION_WINDOW = 10   # 10 seconds for attack detection
    ALERT_COOLDOWN = 60     # 60 seconds between duplicate alerts
    STATISTICS_UPDATE = 1   # 1 second for statistics update

# eBPF Map Configuration
class EbpfMapConfig:
    FLOW_MAP_SIZE = 65536       # Max concurrent flows
    IP_TRACKING_SIZE = 131072   # Max tracked IPs
    BLACKLIST_SIZE = 10000      # Max blacklisted IPs
    SIGNATURE_MAP_SIZE = 1000   # Max attack signatures

# Monitoring Configuration
class MonitoringConfig:
    DASHBOARD_ENABLED = True
    DASHBOARD_PORT = 5000
    DASHBOARD_HOST = '0.0.0.0'
    
    # Metrics export
    METRICS_ENABLED = True
    METRICS_PORT = 9090
    
    # Logging
    LOG_LEVEL = 'INFO' if not DEBUG_MODE else 'DEBUG'
    LOG_FILE = 'logs/ddos_mitigation.log'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5

# Alert Configuration
class AlertConfig:
    ALERT_TO_CONSOLE = True
    ALERT_TO_FILE = True
    ALERT_FILE = 'logs/alerts.log'
    
    # Future: Email, Slack, etc.
    # ALERT_EMAIL = None
    # ALERT_SLACK_WEBHOOK = None

# Traffic Profiling
class ProfilingConfig:
    ENABLE_PROFILING = True
    PROFILE_SAVE_INTERVAL = 300  # Save profile every 5 minutes
    PROFILE_FILE = 'data/traffic_profile.json'
    LEARNING_PERIOD = 3600  # 1 hour initial learning period

# Performance Configuration
class PerformanceConfig:
    # eBPF processing
    EBPF_POLL_TIMEOUT = 100  # milliseconds
    
    # User-space processing
    WORKER_THREADS = 4
    BATCH_SIZE = 1000  # Process statistics in batches
    
    # Memory limits
    MAX_MEMORY_MB = 1024  # 1 GB max memory usage

# Simulation Configuration (for testing)
class SimulationConfig:
    ENABLE_SIMULATOR = False
    NORMAL_TRAFFIC_RATE = 50000  # pps
    ATTACK_TRAFFIC_RATE = 1000000  # pps
    SIMULATION_DURATION = 300  # seconds


# Phase 2: ML Configuration
class MLConfig:
    # Model paths
    MODEL_DIR = 'data/models'
    DEFAULT_MODEL_PATH = 'data/models/ddos_classifier.joblib'
    
    # Dataset paths
    DATASET_DIR = 'data/cic-ddos-2019'
    
    # Training settings
    MAX_TRAINING_FILES = 5
    SAMPLES_PER_FILE = 50000
    TEST_SIZE = 0.2
    VALIDATION_SIZE = 0.1
    
    # Model hyperparameters
    MODEL_TYPE = 'random_forest'
    N_ESTIMATORS = 100
    MAX_DEPTH = 15
    
    # Inference settings
    ML_CONFIDENCE_THRESHOLD = 70.0  # Minimum confidence for ML detection
    HYBRID_SCORE_THRESHOLD = 60.0   # Combined score threshold
    
    # Feature extraction
    FEATURE_WINDOW_SIZE = 10.0  # seconds

# Platform-specific paths
if PLATFORM == 'linux':
    DATA_DIR = '/var/lib/ddos-mitigation'
    LOG_DIR = '/var/log/ddos-mitigation'
else:  # Windows
    DATA_DIR = os.path.join(os.getenv('PROGRAMDATA', 'C:\\ProgramData'), 'ddos-mitigation')
    LOG_DIR = os.path.join(DATA_DIR, 'logs')

# Create directories if they don't exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)
