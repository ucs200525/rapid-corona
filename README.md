# DDoS Mitigation System

A high-performance machine learning-based DDoS mitigation system using eBPF/XDP for ultra-fast packet filtering and statistical anomaly detection.

## Architecture

- **eBPF/XDP Data Plane**: Kernel-level packet filtering achieving 5M+ pps throughput
- **Statistical Anomaly Detection**: User-space control plane for intelligent threat detection
- **Cross-Platform**: Linux (native eBPF/XDP) and Windows (Microsoft eBPF)
- **Simulation Framework**: Test against large-scale volumetric attacks

## Performance Targets (Phase 1)

- ✅ 5M+ pps sustained traffic handling
- ✅ <1 second detection latency for 1M+ pps attacks
- ✅ >10M pps packet drop rate (blacklisted sources)
- ✅ <20% CPU overhead at 5M pps

## Project Structure

```
rapid-corona/
├── src/
│   ├── ebpf/              # eBPF/XDP kernel programs
│   ├── anomaly_detector.py
│   ├── traffic_monitor.py
│   ├── traffic_profiler.py
│   ├── metrics_collector.py
│   ├── dashboard.py
│   └── alert_system.py
├── simulation/            # Traffic simulation
│   ├── traffic_simulator.py
│   └── attack_scenarios.py
├── tests/                 # Testing and benchmarks
│   ├── test_detector.py
│   ├── test_simulator.py
│   └── benchmark.py
├── config.py
├── main.py
└── requirements.txt
```

## Quick Start

### Linux Setup

```bash
# Install eBPF dependencies
sudo ./setup_ebpf.sh

# Install Python dependencies
pip install -r requirements.txt

# Load and run
sudo python main.py --interface eth0
```

### Windows Setup

```powershell
# Install Microsoft eBPF
.\setup_ebpf.ps1

# Install Python dependencies
pip install -r requirements.txt

# Run
python main.py --interface "Ethernet"
```

## Development Phases

- **Phase 1** (Current): Baseline traffic anomaly detection with eBPF/XDP
- **Phase 2** (Future): ML-based classification for attack vs. legitimate surges
- **Phase 3** (Future): Auto signature generation and comparative benchmarking

## License

MIT License
