# 🛡️ Hybrid XDP & ML-Based DDoS Mitigation System

This project is a high-performance **DDoS detection and mitigation system** that combines the speed of **eBPF/XDP** (Express Data Path) for kernel-level packet filtering with the intelligence of **Machine Learning (Random Forest)** for traffic classification.

By leveraging XDP, the system can block malicious traffic **before it even reaches the operating system's network stack**, achieving extremely high throughput and low latency.

---

## 🚀 Key Features

*   **Kernel-Level Blocking (XDP)**: Uses **eBPF (Extended Berkeley Packet Filter)** to hook into the network driver. Drops malicious packets directly at the NIC level.
*   **Intelligent Anomaly Detection**:
    - **Baseline Profiling**: Automatically learns normal traffic patterns (PPS, Protocol distribution) during a learning phase.
    - **ML Classification**: Uses a trained **Random Forest Classifier** to analyze traffic features (Entropy, Flow duration, Flag counts) and detect sophisticated attacks.
*   **Real-Time Dashboard**: A modern, dark-themed dashboard built with **Flask** and **Chart.js**.
*   **Distributed Attack Simulation**: Includes a powerful **Attack Simulator** (`attack_simulator.py`) capable of generating UDP/ICMP Floods, TCP SYN Floods, and HTTP Floods with **Distributed Botnet Attacks** (Spoofed Source IPs).

---

## 📂 Project Structure & File Descriptions

### Core Controller & UI
- **`main.py`**: The central entry point. Orchestrates the loading of the XDP filter, the starting of the dashboard, and the periodic polling of kernel metrics.
- **`src/dashboard.py`**: A Flask-based web application that provides a real-time visualization of network traffic, detection events, and the current blacklist.
- **`src/traffic_monitor.py`**: Acts as a bridge between the kernel and userspace. It reads BPF maps (stats) and writes to them (blacklist).

### Mitigation & Detection Logic
- **`src/anomaly_detector.py`**: The "brain" of the system. It compares current traffic against the baseline and makes the final decision on whether to blacklist an IP.
- **`src/alert_system.py`**: Manages notifications and logging for detected attacks.
- **`src/metrics_collector.py`**: Periodically samples traffic stats to feed into the anomaly detector and dashboard.

### Kernel Plane (eBPF/XDP)
- **`src/ebpf/xdp_filter.c`**: The C program compiled to BPF bytecode. It handles the actual dropping (`XDP_DROP`) of blacklisted IPs and the initial classification (`XDP_PASS`).
- **`src/ebpf/xdp_maps.h`**: Defines the shared memory structures (Hash Maps and Arrays) used for communication between the C kernel program and Python userspace.

### Machine Learning (ML)
- **`src/ml/feature_extractor.py`**: Converts raw packet statistics into numerical features (e.g., protocol ratios, entropy) for the ML model.
- **`src/ml/ml_classifier.py`**: Wraps the Random Forest model and provides a simple `predict()` interface to the anomaly detector.
- **`src/ml/model_trainer.py`**: Utility for training the Random Forest model using historical DDoS datasets (like CIC-DDoS2019).

### Simulation & Testing
- **`attack_simulator.py`**: A multi-functional tool for testing the system. Supports various attack vectors and **Spoofed IP** simulation to test botnet defense.
- **`run_attack_demo.py`**: A high-level automation script that simulates a multi-phase attack (Baseline -> UDP Flood -> SYN Flood) to showcase the system's capabilities on the dashboard.

---
## 🏗️ System Architecture

1.  **Ingress Filter (Kernel)**: The `XDP_DROP` hook intercepts packets.
2.  **Shared Memory (BPF Maps)**: Stats flow up; Blacklist flows down.
3.  **Analysis Engine (Python)**: Anomaly detector runs Every 1s.
4.  **Action**: Offenders added to `blacklist_map` (instant block).
5.  **Visualization**: Dashboard reflects the current state.

---

## 🛠️ Installation & Usage

### Prerequisites
- **Linux OS** (Kernel 4.15+ for XDP support).
- **Python 3.8+**.
- **Root privileges** (Sudo) for eBPF loading.

### Quick Start
1.  **Install dependencies**:
    `sudo apt install -y bpfcc-tools clang llvm libelf-dev python3-pip`
    `sudo pip3 install scapy flask joblib scikit-learn numpy pandas`
2.  **Setup Virtual Network**:
    `sudo ip link add veth0 type veth peer name veth1 && sudo ip link set veth0 up && sudo ip link set veth1 up`
    `sudo ip addr add 192.168.99.1/24 dev veth0 && sudo ip addr add 192.168.99.2/24 dev veth1`
3.  **Run the system** (Victim):
    `sudo python3 main.py --interface veth1 --mode generic --dashboard`
4.  **Launch the demo attack** (Attacker):
    `sudo python3 attack_simulator.py --type mixed --distributed --target 192.168.99.2 --interface veth0`

---

## ⚠️ Disclaimer
This tool is for **educational and testing purposes only**. Using DDoS tools on networks you do not own is illegal.

---
*Developed for research into hybrid kernel/ML defense mechanisms.*
