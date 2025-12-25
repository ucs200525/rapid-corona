# DDoS Mitigation System - Usage Guide

## Overview

A machine learning-based DDoS mitigation system with real-time traffic analysis and automated defense.

- **Phase 1**: Statistical anomaly detection with eBPF/XDP
- **Phase 2**: ML-based classification using CIC-DDoS-2019 trained models

---

## Prerequisites

### Linux
- Linux kernel 4.18+ with XDP support
- Ubuntu 20.04+, RHEL 8+, or compatible
- Root/sudo access
- Python 3.8+

### Dependencies
```bash
pip3 install -r requirements.txt
```

Required packages: `numpy`, `pandas`, `scipy`, `flask`, `scikit-learn`, `joblib`, `psutil`, `coloredlogs`

---

## Quick Start


### 1. Install & Setup

```bash
# Clone/navigate to project
cd rapid-corona

# Run setup (Linux)
sudo ./setup_ebpf.sh

# Compile eBPF programs
cd src/ebpf && make && cd ../..

# Install Python dependencies
pip3 install -r requirements.txt
```

### 2. Run the System

```bash
# Basic - Statistical detection only (Phase 1)
sudo python3 main.py --interface enp0s3 --dashboard

# With ML classification (Phase 2)
sudo python3 main.py --interface enp0s3 --train-model --dashboard

# With pre-trained ML model
sudo python3 main.py --interface enp0s3 --ml-model data/models/ddos_classifier.joblib --dashboard
```

### 3. Access Dashboard
Open **http://localhost:5000** in your browser.

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--interface, -i` | Network interface to monitor | eth0 |
| `--mode, -m` | XDP mode: native, generic, offload | native |
| `--dashboard` | Enable web dashboard | False |
| `--port, -p` | Dashboard port | 5000 |
| `--debug, -d` | Enable debug logging | False |
| `--ml-model` | Path to trained ML model | None |
| `--train-model` | Train ML model before starting | False |
| `--data-path` | Path to CIC-DDoS-2019 dataset | data/cic-ddos-2019 |

### Examples

```bash
# Generic XDP mode (works on all interfaces)
sudo python3 main.py --interface enp0s3 --mode generic --dashboard

# With specific dashboard port
sudo python3 main.py --interface eth0 --dashboard --port 8080

# Debug mode with ML
sudo python3 main.py --interface eth0 --ml-model data/models/ddos_classifier.joblib --debug
```

---

## Phase 2: ML Classification

### Training a Model

#### Option 1: Synthetic Data (Quick Test)
```bash
# Train with auto-generated synthetic data
python3 -m src.ml.model_trainer train --synthetic
```

#### Option 2: CIC-DDoS-2019 Dataset (Production)
```bash
# 1. Download dataset from: https://www.unb.ca/cic/datasets/ddos-2019.html
# 2. Place CSV files in data/cic-ddos-2019/

# 3. Train model
python3 -m src.ml.model_trainer train --data-path data/cic-ddos-2019/

# 4. Evaluate model
python3 -m src.ml.model_trainer evaluate --model-path data/models/ddos_classifier.joblib

# 5. Benchmark inference speed
python3 -m src.ml.model_trainer benchmark --model-path data/models/ddos_classifier.joblib
```

### Model Training Options

```bash
python3 -m src.ml.model_trainer train \
    --data-path data/cic-ddos-2019/ \
    --model-path data/models/my_model.joblib \
    --model-type random_forest \
    --n-estimators 100 \
    --max-depth 15 \
    --max-files 5 \
    --samples-per-file 50000
```

### What the ML Model Detects

| Attack Type | Description |
|-------------|-------------|
| SYN_Flood | TCP SYN flood attacks |
| UDP_Flood | UDP volumetric attacks |
| DrDoS_UDP | Distributed reflection UDP |
| DrDoS_DNS | DNS amplification attacks |
| DrDoS_LDAP | LDAP amplification |
| DDoS_Generic | Other attack patterns |
| BENIGN | Normal traffic |

---

## Detection Methods

### Phase 1: Statistical Detection

1. **Absolute Thresholds** - Alert when PPS exceeds limits
2. **Statistical Deviation** - Detect traffic > 3.5 sigma from baseline
3. **Rate of Change** - Flag sudden spikes (>5x increase)
4. **Protocol Distribution** - Monitor TCP/UDP/ICMP ratios
5. **IP Entropy** - Low entropy = botnet, high = flash crowd
6. **SYN Flood Detection** - Track excessive SYN packets per IP

### Phase 2: ML Classification

- **Random Forest classifier** trained on 64 CIC-DDoS-2019 features
- **Real-time feature extraction** from live traffic
- **Hybrid detection** combining statistical + ML scores
- **Attack type classification** with confidence scores

### Hybrid Scoring

The system combines both methods:
- ML confidence > 85% → Trust ML detection
- Both agree → High confidence detection
- Statistical score > 70 → Trust statistical
- Combined score > 60 → Likely attack

---

## Web Dashboard

Access at **http://localhost:5000**

### Dashboard Cards

| Card | Information |
|------|-------------|
| Real-time Status | Interface, current PPS, baseline PPS, drop rate |
| Traffic Statistics | Total packets/bytes, dropped/passed counts |
| Protocol Distribution | TCP, UDP, ICMP, Other packet counts |
| Baseline Profile | Mean PPS, std dev, samples, learning status |
| Top IPs | Highest traffic source IPs |
| Blacklist | Blocked IP addresses |
| **ML Classification** | Model accuracy, predictions, attacks detected, inference time |
| **Feature Importance** | Top features contributing to ML predictions |
| Recent Alerts | Alert history with severity |

---

## Configuration

Edit `config.py` to customize:

### Detection Thresholds
```python
class DetectionThresholds:
    ALERT_PPS_THRESHOLD = 500      # Alert threshold
    ATTACK_PPS_THRESHOLD = 2000    # Attack threshold
    SIGMA_MULTIPLIER = 2.0         # Statistical deviation
    MIN_ENTROPY = 3.0              # IP diversity threshold
```

### ML Configuration
```python
class MLConfig:
    DEFAULT_MODEL_PATH = 'data/models/ddos_classifier.joblib'
    ML_CONFIDENCE_THRESHOLD = 70.0   # Min confidence for ML detection
    HYBRID_SCORE_THRESHOLD = 60.0    # Combined score threshold
    N_ESTIMATORS = 100               # Random Forest trees
    MAX_DEPTH = 15                   # Tree depth
```

### Time Windows
```python
class TimeWindows:
    BASELINE_WINDOW = 300   # 5 min baseline learning
    DETECTION_WINDOW = 10   # 10 sec detection window
    ALERT_COOLDOWN = 60     # 60 sec between alerts
```

---

## Testing

### Run Unit Tests
```bash
# All tests
python3 -m pytest tests/ -v

# ML classifier tests
python3 -m pytest tests/test_ml_classifier.py -v

# Anomaly detector tests
python3 -m pytest tests/test_detector.py -v
```

### Benchmark Performance
```bash
# List scenarios
python3 tests/benchmark.py --list

# Run specific scenario
python3 tests/benchmark.py --scenario "Large UDP Flood"

# Test packet rates
python3 tests/benchmark.py --rate 100000 --rate 500000
```

---

## Traffic Simulation

### Generate Attack Traffic
```bash
python3 attack_simulator.py --type udp_flood --rate 10000 --duration 60
python3 attack_simulator.py --type syn_flood --rate 5000 --duration 30
```

### Attack Types
- `udp_flood` - High-volume UDP packets
- `syn_flood` - TCP SYN flood
- `icmp_flood` - ICMP echo flood
- `http_flood` - HTTP GET flood
- `mixed` - Multi-vector attack

---

## Files & Directories

```
rapid-corona/
├── main.py                 # Main entry point
├── config.py               # Configuration
├── requirements.txt        # Python dependencies
├── src/
│   ├── anomaly_detector.py # Statistical + ML detection
│   ├── traffic_monitor.py  # eBPF traffic monitoring
│   ├── dashboard.py        # Web dashboard
│   ├── ml/                 # ML module (Phase 2)
│   │   ├── data_loader.py      # Dataset loading
│   │   ├── feature_extractor.py # Real-time features
│   │   ├── ml_classifier.py    # Random Forest classifier
│   │   └── model_trainer.py    # Training CLI
│   └── ebpf/               # eBPF programs
├── data/
│   ├── models/             # Trained ML models
│   └── cic-ddos-2019/      # Dataset (user-provided)
├── logs/                   # Log files
└── tests/                  # Unit tests
```

---

## Troubleshooting

### eBPF Won't Load
```bash
# Check kernel version (need 4.18+)
uname -r

# Try generic mode
sudo python3 main.py --interface eth0 --mode generic
```

### Permission Denied
```bash
# Require root for XDP
sudo python3 main.py --interface eth0
```

### ML Model Not Loading
```bash
# Ensure model exists
ls -la data/models/

# Train a new model
python3 -m src.ml.model_trainer train --synthetic
```

### Missing Dependencies
```bash
pip3 install scikit-learn joblib
```

---

## Performance Expectations

| Metric | Target |
|--------|--------|
| Packet handling | 5M+ pps |
| Detection latency | <1 second |
| ML inference | <10 ms per prediction |
| CPU overhead | <20% at 5M pps |
| Drop rate | >10M pps (blacklisted) |

---

## Log Files

| File | Content |
|------|---------|
| `logs/ddos_mitigation.log` | Main application log |
| `logs/alerts.log` | Alert history |
| `data/traffic_profile.json` | Learned traffic baseline |
| `data/models/*.joblib` | Trained ML models |

---

## License

MIT License
