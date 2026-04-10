# 🛡️ Hybrid XDP & ML-Based DDoS Mitigation System

This project is a high-performance **DDoS detection and mitigation system** that combines the speed of **eBPF/XDP** (Express Data Path) for kernel-level packet filtering with the intelligence of **Machine Learning (Random Forest)** for traffic classification.

By leveraging XDP, the system can block malicious traffic **before it even reaches the operating system's network stack**, achieving extremely high throughput and low latency.

---

## 🚀 Key Features

### 1. **Kernel-Level Blocking (XDP)**
   - Uses **eBPF (Extended Berkeley Packet Filter)** to hook into the network driver.
   - Drops malicious packets directly at the NIC level.
   - Extremely low CPU overhead compared to userspace firewalls (iptables/nftables).
   - Blocks based on a dynamic **Blacklist Map** shared between kernel and userspace.

### 2. **Intelligent Anomaly Detection**
   - **Baseline Profiling**: Automatically learns normal traffic patterns (PPS, Protocol distribution) during a learning phase.
   - **ML Classification**: Uses a trained **Random Forest Classifier** to analyze traffic features (Entropy, Flow duration, Flag counts) and detect sophisticated attacks.
   - **Hybrid Approach**: Combines statistical thresholds (for volumetric floods) with ML (for subtle L7/protocol attacks).

### 3. **Persistent Blacklisting**
   - Automatically saves blocked IPs to `data/blacklist.json`.
   - Restores the blacklist on system restart, ensuring persistent protection against known attackers.
   - Supports manual addition/removal of IPs via the dashboard capabilities.

### 4. **Real-Time Dashboard**
   - **Web Interface**: A modern, dark-themed dashboard built with **Flask** and **Chart.js**.
   - **Live Metrics**: Displays current PPS (Packets Per Second), Drop Rate, Top Attacking IPs, and ML Confidence.
   - **Protocol Analysis**: Visualizes TCP vs UDP vs ICMP traffic distribution.
   - **Attack Alerts**: Shows a history of recent detection events with severity scores.

### 5. **Distributed Attack Simulation**
   - Includes a powerful **Attack Simulator** (`attack_simulator.py`) capable of generating:
     - UDP/ICMP Floods
     - TCP SYN Floods
     - HTTP Floods
     - **Distributed Botnet Attacks** (Spoofed Source IPs)
   - Supports high-speed packet injection using raw sockets (Scapy L2).

---

## 🏗️ System Architecture

1.  **Ingress Filter (`src/ebpf/xdp_filter.c`)**:
    - The C program compiled into eBPF bytecode.
    - Inspects every incoming packet header.
    - Checks the **Blacklist Map**. If the Source IP is blacklisted -> `XDP_DROP`.
    - Updates **Statistics Maps** (Per-IP packet counts, Protocol counts) -> `XDP_PASS`.

2.  **Userspace Controller (`main.py`)**:
    - Loads the XDP program into the kernel.
    - Periodically reads the **Statistics Maps** from the kernel.
    - Feeds traffic data into the **Anomaly Detector**.
    - Updates the dashboard and logs.

3.  **Anomaly Detector (`src/anomaly_detector.py`)**:
    - Compares current traffic against the learned **Baseline Profile**.
    - Runs the **ML Classifier** on traffic features.
    - If an attack is detected:
        - Identifies the top offending IPs.
        - Adds them to the **Blacklist Map** (blocking them instantly in the kernel).
        - Triggers an alert.

---

## 📦 Installation & Requirements

### Prerequisites
- **Linux OS** (Kernel 4.15+ for XDP support).
- **Python 3.8+**.
- **Root privileges** (Sudo) are required to load eBPF programs and send raw packets.

### Install Dependencies
```bash
# System dependencies (for eBPF compilation)
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc clang llvm libelf-dev python3-pip tcpdump

# Python dependencies
sudo pip3 install scapy flask joblib scikit-learn numpy pandas
```

---

## 🛠️ Usage

### 1. Setup Network (Local Testing)
Since XDP filters ingress traffic, testing on a single machine requires a virtual ethernet pair (`veth`).

```bash
# Create veth0 <-> veth1 pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 192.168.99.1/24 dev veth0
sudo ip addr add 192.168.99.2/24 dev veth1
```

### 2. Run the DDoS System
Run the system on the "victim" interface (`veth1`).

```bash
echo "password" | sudo -S python3 main.py --interface veth1 --mode generic --dashboard
```
*   **--interface**: Network interface to protect.
*   **--mode**: `native` (driver support) or `generic` (software emulation, works on all NICs).
*   **--dashboard**: Starts the web UI at `http://localhost:5000`.

### 3. Simulate an Attack
Run the simulator on the "attacker" interface (`veth0`).

```bash
# Mixed attack from a distributed botnet (100+ random persistent IPs)
sudo python3 attack_simulator.py --type mixed --distributed --target 192.168.99.2 --duration 30 --interface veth0
```
*   **--distributed**: Spoofs random source IPs (simulating a botnet).
*   **--target**: Must match the IP of the victim interface (`veth1`).
*   **--interface**: Must be the attacker interface (`veth0`).

---

## 📊 Dashboard

The dashboard is accessible at **`http://localhost:5000`**.

- **Real-time Status**: Shows current traffic load vs baseline.
- **Top IPs**: Lists the IP addresses sending the most packets.
- **Blacklist**: Shows IPs currently blocked by the XDP filter.
- **ML Analysis**: Displays which features (e.g., "High UDP count") triggered the detection.

---

## 📂 Project Structure

```
rapid-corona/
├── main.py                 # Entry point (Controller)
├── attack_simulator.py     # DDoS Simulation Tool
├── run_attack_demo.py      # Automated Demo Script (Dashboard Direct)
├── run.md                  # Quick Start Guide
├── requirements.txt        # Python dependencies
├── src/
│   ├── anomaly_detector.py # Logic for detection & blocking
│   ├── dashboard.py        # Flask Web App
│   ├── traffic_monitor.py  # Interface to eBPF maps
│   ├── ml/                 # Machine Learning modules
│   └── ebpf/
│       ├── xdp_filter.c    # CORE XDP C Program (Kernel)
│       └── xdp_maps.h      # BPF Map definitions
├── data/
│   ├── blacklist.json      # Persistent blocked IPs
│   ├── traffic_profile.json# Learned baseline stats
│   └── models/             # Trained ML models (.joblib)
└── logs/                   # System logs
```

---

## ⚠️ Disclaimer
This tool is for **educational and testing purposes only**. Using DDoS tools on networks you do not own is illegal. The XDP filter is powerful and can block all traffic if misconfigured. Always test in a controlled environment.
