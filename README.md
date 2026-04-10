# 🛡️ Hybrid XDP & ML-Based DDoS Mitigation System

This project is a high-performance **DDoS detection and mitigation system** that combines the speed of **eBPF/XDP** (Express Data Path) for kernel-level packet filtering with the intelligence of **Machine Learning (Random Forest)** for traffic classification.

By leveraging XDP, the system can block malicious traffic **before it even reaches the operating system's network stack**, achieving extremely high throughput and low latency.

---

## 💡 Why This Project Matters

Traditional DDoS mitigation systems operate in user space, leading to higher latency and resource usage.  
This project demonstrates how combining kernel-level filtering (XDP) with intelligent ML-based detection can create a highly efficient and scalable modern defense system.

---

## 🚀 Key Features

* **Kernel-Level Blocking (XDP)**: Uses **eBPF (Extended Berkeley Packet Filter)** to hook into the network driver and drop malicious packets at the NIC level.
* **Intelligent Anomaly Detection**:
  - **Baseline Profiling**: Learns normal traffic patterns (PPS, protocol distribution).
  - **ML Classification**: Uses a **Random Forest Classifier** to detect sophisticated attacks based on traffic features.
* **Real-Time Dashboard**: Built using **Flask** and **Chart.js** for live monitoring.
* **Distributed Attack Simulation**: Supports UDP, ICMP, TCP SYN, and HTTP floods with spoofed IP-based botnet simulation.

---

## 🧰 Tech Stack

- **Kernel Programming:** eBPF, XDP (C)
- **Backend:** Python, Flask
- **Machine Learning:** Scikit-learn (Random Forest)
- **Networking:** Linux Networking Stack, BPF Maps
- **Visualization:** Chart.js
- **Tools:** BCC, libbpf, Scapy

---

## 📊 Performance & Results

- Achieves high-throughput packet processing using XDP at kernel level.
- Successfully mitigates UDP, SYN, and ICMP flood attacks in real-time.
- Reduces attack impact with low-latency filtering before packets reach user space.
- Demonstrates effective attack detection using ML-based classification.
- Maintains stable performance under simulated distributed attack scenarios.

---

## 📂 Project Structure & File Descriptions

### Core Controller & UI
- **`main.py`**: Entry point; loads XDP program, starts dashboard, and manages system flow.
- **`src/dashboard.py`**: Flask-based dashboard for real-time visualization.
- **`src/traffic_monitor.py`**: Interfaces between kernel (BPF maps) and user space.

### Mitigation & Detection Logic
- **`src/anomaly_detector.py`**: Core decision engine comparing traffic with baseline.
- **`src/alert_system.py`**: Handles logging and alerting.
- **`src/metrics_collector.py`**: Collects traffic stats periodically.

### Kernel Plane (eBPF/XDP)
- **`src/ebpf/xdp_filter.c`**: Handles packet filtering (`XDP_DROP` / `XDP_PASS`).
- **`src/ebpf/xdp_maps.h`**: Defines shared BPF maps.

### Machine Learning (ML)
- **`src/ml/feature_extractor.py`**: Converts traffic stats into ML features.
- **`src/ml/ml_classifier.py`**: Random Forest prediction wrapper.
- **`src/ml/model_trainer.py`**: Trains ML model using datasets (e.g., CIC-DDoS2019).

### Simulation & Testing
- **`attack_simulator.py`**: Generates multiple DDoS attack types.
- **`run_attack_demo.py`**: Automates multi-phase attack simulation.

---

## 🏗️ System Architecture

1. **Ingress Filter (Kernel)**: XDP intercepts packets.
2. **Shared Memory (BPF Maps)**: Stats → User space, Blacklist → Kernel.
3. **Analysis Engine (Python)**: Runs anomaly detection every second.
4. **Mitigation Action**: Malicious IPs added to blacklist.
5. **Visualization**: Dashboard updates in real-time.

---

## 🧩 Challenges & Learnings

- Efficient kernel ↔ user space communication using BPF maps.
- Designing low-latency filtering without affecting legitimate traffic.
- Feature engineering for ML-based anomaly detection.
- Simulating realistic distributed attacks using spoofed IP traffic.

---

## 🔮 Future Improvements

- Integration of deep learning models for adaptive detection.
- IPv6 traffic support.
- Kubernetes-based scalable deployment.
- Integration with SIEM tools for enterprise monitoring.

---

## 🛠️ Installation & Usage

### Prerequisites
- Linux OS (Kernel 4.15+)
- Python 3.8+
- Root privileges

### Quick Start

1. Install dependencies: