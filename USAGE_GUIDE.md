# DDoS Mitigation System - Usage Guide

## Phase 1: Baseline Traffic Anomaly Detection

This guide covers installation, configuration, and usage of the Phase 1 DDoS mitigation system.

## Prerequisites

### Linux
- Linux kernel 4.18+ with XDP support
- Ubuntu 20.04+, RHEL 8+, or compatible distribution
- Root/sudo access
- Network interface with XDP support (most modern NICs)

### Windows  
- Windows 11 or Windows Server 2022+
- Administrator privileges
- Microsoft eBPF runtime

## Installation

### Quick Start (Linux)

```bash
# 1. Clone or navigate to project directory
cd rapid-corona

# 2. Run setup script
sudo ./setup_ebpf.sh

# 3. Compile eBPF programs
cd src/ebpf
make
cd ../..

# 4. Install Python dependencies
pip install -r requirements.txt
```

### Quick Start (Windows)

```powershell
# Run as Administrator
.\setup_ebpf.ps1

# Install Python dependencies
pip install -r requirements.txt

# Build eBPF programs (requires clang)
cd src\ebpf
# Follow Microsoft eBPF build instructions
```

## Basic Usage

### Starting the System

```bash
# Linux - with native XDP (best performance)
sudo python main.py --interface eth0

# Linux - with generic XDP (works on all interfaces)
sudo python main.py --interface eth0 --mode generic

# Windows
python main.py --interface "Ethernet"
```

### Command Line Options

- `--interface, -i`: Network interface to monitor (default: eth0/Ethernet)
- `--mode, -m`: XDP mode - native, generic, or offload (default: native)
- `--debug, -d`: Enable debug logging

### Web Dashboard

Access the real-time monitoring dashboard at: `http://localhost:5000`

The dashboard shows:
- Traffic statistics (packets, bytes, drop rate)
- Protocol distribution
- Baseline profile status
- Blacklisted IPs
- Recent alerts

## Configuration

Edit `config.py` to customize:

### Detection Thresholds
```python
class DetectionThresholds:
    ALERT_PPS_THRESHOLD = 100000  # Alert at 100k pps
    ATTACK_PPS_THRESHOLD = 500000  # Definite attack at 500k pps
    SIGMA_MULTIPLIER = 3.5  # Statistical deviation threshold
    MIN_ENTROPY = 3.0  # IP diversity threshold
```

### Time Windows
```python
class TimeWindows:
    BASELINE_WINDOW = 300  # 5 minutes baseline learning
    DETECTION_WINDOW = 10   # 10 second detection window
    ALERT_COOLDOWN = 60     # 60 seconds between duplicate alerts
```

## Testing & Benchmarking

### Run Unit Tests

```bash
# All tests
pytest tests/ -v

# Specific test
pytest tests/test_detector.py -v
pytest tests/test_simulator.py -v
```

### Benchmark Performance

```bash
# List available scenarios
python tests/benchmark.py --list

# Run specific scenario
python tests/benchmark.py --scenario "Large UDP Flood"

# Run all medium scale scenarios
python tests/benchmark.py --scale medium

# Test specific packet rates
python tests/benchmark.py --rate 100000 --rate 500000 --rate 1000000

# Save results to file
python tests/benchmark.py --scale large --output results.json
```

## Traffic Simulation

The traffic simulator can generate various attack patterns for testing:

### Attack Types
- **UDP Flood**: High-volume UDP packets
- **SYN Flood**: TCP SYN packets overwhelming connections
- **ICMP Flood**: ICMP echo request flood
- **HTTP Flood**: Application-layer GET request flood
- **Mixed Attack**: Multi-vector attack combining the above

### Pre-defined Scenarios
- **Small UDP Flood**: 10k pps (testing)
- **Medium SYN Flood**: 100k pps
- **Large UDP Flood**: 1M pps
- **Hyper-Volumetric UDP**: 5M pps (India IX scale)
- **Flash Crowd**: 500k pps legitimate traffic surge

## Understanding Detection

### Anomaly Detection Methods

The system uses multiple statistical methods:

1. **Absolute Thresholds**
   - Alert if PPS exceeds configured thresholds
   - Immediate detection of obvious attacks

2. **Statistical Deviation**
   - Calculate standard deviation from learned baseline
   - Detect traffic > 3.5 sigma from normal

3. **Rate of Change**
   - Flag sudden traffic spikes (>5x increase)
   - Characteristic of attack onset

4. **Protocol Distribution**
   - Monitor TCP/UDP/ICMP ratios
   - Detect protocol-specific floods

5. **IP Entropy**
   - Low entropy = concentrated sources (botnet)
   - High entropy = diverse sources (flash crowd)

6. **SYN Flood Detection**
   - Track excessive SYN packets per IP
   - eBPF-level counting for performance

### Baseline Learning

The system learns normal traffic patterns:
- **Learning Period**: First 5 minutes (configurable)
- **Adaptive Updates**: Continuous slow adaptation after learning
- **Persistence**: Baseline saved to `data/traffic_profile.json`

## Automated Mitigation

When an attack is detected:

1. **Alert Generated**: High/medium severity alert
2. **Auto-Blacklisting**: Top attacking IPs added to blacklist
3. **eBPF Filtering**: Blacklisted traffic dropped in kernel
4. **Logging**: All events logged to `logs/`

### Manual Blacklist Management

The system auto-blacklists IPs during attacks. You can also manage manually via the API (dashboard integration coming in Phase 2).

## Performance Expectations

### Phase 1 Targets (eBPF/XDP)
- ✅ 5M+ pps sustained traffic handling
- ✅ <1 second detection latency (1M+ pps attacks)
- ✅ >10M pps packet drop rate (blacklisted)
- ✅ <20% CPU overhead at 5M pps

### Comparison vs. Traditional Solutions
- **vs. iptables**: 10-100x faster packet processing
- **vs. Python Scapy**: 100-1000x higher throughput
- **vs. Traditional appliances**: Comparable performance at fraction of cost

## Troubleshooting

### eBPF Program Won't Load

```bash
# Check kernel version
uname -r  # Should be 4.18+

# Check XDP support
ip link show dev eth0  # Look for XDP in features

# Try generic mode instead
sudo python main.py --interface eth0 --mode generic
```

### Permission Denied

Linux XDP programs require root:
```bash
sudo python main.py --interface eth0
```

### No Traffic Detected

- Verify correct interface: `ip addr` or `ifconfig`
- Check if traffic is flowing: `sudo tcpdump -i eth0 -c 10`
- Ensure eBPF program loaded: Check logs for success message

### High CPU Usage

- Switch to native XDP mode (if not already)
- Reduce statistics update frequency in `config.py`
- Ensure eBPF program is compiled with optimizations (-O2)

## Log Files

- **Main log**: `logs/ddos_mitigation.log`
- **Alert log**: `logs/alerts.log`
- **Profile data**: `data/traffic_profile.json`

## Next Steps (Phase 2)

After completing Phase 1, Phase 2 will add:
- ML-based classification (distinguish attacks from flash crowds)
- Advanced feature engineering
- Model training on collected traffic data
- Enhanced dashboard with ML insights

## Next Steps (Phase 3)

Phase 3 will add:
- Auto signature generation
- Advanced traffic shaping
- Comparative benchmarking vs. commercial solutions
- Production deployment guides

## Support & Contribution

This is a research/educational project for DDoS mitigation. Contributions welcome!

## License

MIT License
