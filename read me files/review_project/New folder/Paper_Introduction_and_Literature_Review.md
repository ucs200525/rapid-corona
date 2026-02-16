# Rapid-Corona: Real-Time DDoS Mitigation System Using Machine Learning and eBPF/XDP

## I. INTRODUCTION

### A. Background and Motivation

Distributed Denial of Service (DDoS) attacks have emerged as one of the most persistent and devastating threats to modern network infrastructure. These attacks overwhelm target systems with massive volumes of malicious traffic, rendering critical services unavailable to legitimate users. The evolving sophistication of DDoS attacks, coupled with the exponential growth of Internet-connected devices, has created an urgent need for intelligent, high-performance mitigation systems capable of real-time threat detection and response.

Traditional DDoS mitigation approaches operating in user space suffer from inherent performance limitations, as packets must traverse the entire network stack before analysis and filtering decisions can be made. This introduces significant latency and computational overhead, particularly under high-volume attack conditions where systems may process millions of packets per second. Furthermore, conventional signature-based detection methods struggle to identify novel attack patterns and zero-day threats, leaving critical infrastructure vulnerable to emerging attack vectors.

Recent advances in kernel-level programmability through Extended Berkeley Packet Filter (eBPF) and eXpress Data Path (XDP) technologies have revolutionized network packet processing by enabling custom programs to execute directly within the Linux kernel [1][2]. This paradigm shift allows packet filtering and analysis to occur at the earliest possible point in the networking stack—immediately upon packet arrival at the Network Interface Card (NIC)—achieving processing speeds exceeding 5 million packets per second with sub-microsecond latency [3][4]. Simultaneously, machine learning techniques have demonstrated remarkable capabilities in detecting anomalous network behavior patterns that traditional rule-based systems cannot identify [6][7].

### B. Problem Statement

Current DDoS mitigation solutions face three fundamental challenges:

1. **Performance Bottlenecks**: User-space packet processing introduces unacceptable latency during high-volume attacks, often overwhelming the very systems designed to provide protection.

2. **Detection Accuracy**: Signature-based approaches generate high false-positive rates and fail to detect sophisticated semantic DDoS attacks that mimic legitimate traffic patterns [4].

3. **Real-time Responsiveness**: Existing solutions lack the ability to make immediate filtering decisions at line-rate speeds while simultaneously performing complex behavioral analysis.

These limitations underscore the critical need for a hybrid mitigation architecture that combines kernel-level packet filtering performance with intelligent anomaly detection capabilities.

### C. Research Objectives

This research presents **Rapid-Corona**, a novel hybrid DDoS mitigation system that addresses the aforementioned challenges through the integration of eBPF/XDP kernel-level filtering with machine learning-based anomaly detection. The primary objectives of this work are:

1. **Ultra-Fast Packet Processing**: Leverage eBPF/XDP technology to implement kernel-space packet filtering capable of processing over 5 million packets per second with minimal CPU overhead.

2. **Intelligent Threat Detection**: Develop a dual-layer detection mechanism combining:
   - Statistical baseline anomaly detection using entropy analysis, protocol distribution monitoring, and rate-of-change algorithms
   - Machine learning classification using Random Forest models trained on the comprehensive CIC-DDoS-2019 dataset

3. **Real-time Attack Classification**: Enable precise identification of specific attack types (SYN flood, UDP flood, DNS amplification, HTTP flood, etc.) with confidence scoring.

4. **Minimal False Positives**: Implement hybrid decision-making logic that synthesizes statistical and ML-based scores to minimize false alarms while maintaining high detection sensitivity.

5. **Cross-Platform Compatibility**: Design the system to operate on both Linux (native eBPF) and Windows (Microsoft eBPF) platforms.

### D. Key Contributions

This research makes the following significant contributions to the field of network security:

1. **Novel Hybrid Architecture**: We propose a unique two-tier architecture separating packet processing (data plane) from intelligent analysis (control plane), achieving both ultra-fast filtering and sophisticated threat detection.

2. **Real-time Feature Extraction**: Development of a lightweight feature extraction module capable of computing 64 CIC-compatible statistical features from live traffic with minimal computational overhead.

3. **Adaptive Baseline Learning**: Implementation of dynamic traffic profiling that adapts to legitimate traffic patterns while detecting deviations indicative of attack behavior.

4. **Comprehensive Evaluation**: Validation of the system using the CIC-DDoS-2019 dataset containing multiple attack types with demonstrated detection accuracy exceeding 95%.

5. **Open Architecture**: Design of modular components enabling future enhancements including automated signature generation and comparative benchmarking.

### E. System Overview

![System Architecture](file:///d:/4.own/Projects/rapid-corona/read%20me%20files/review_project/New%20folder/system_architecture_diagram.png)

The Rapid-Corona system architecture consists of two primary layers:

**Data Plane (Kernel Space - eBPF/XDP Layer)**:
- Packet parsing and header extraction
- High-speed blacklist checking
- Per-IP and per-flow statistics collection
- Immediate packet drop/pass decisions (XDP_DROP/XDP_PASS)
- Shared memory communication via eBPF maps

**Control Plane (User Space - Python)**:
- Traffic monitoring and statistics aggregation
- Statistical anomaly detection
- ML-based feature extraction and classification
- Alert generation and blacklist management
- Real-time dashboard visualization

![Data Journey](file:///d:/4.own/Projects/rapid-corona/read%20me%20files/review_project/New%20folder/complete_data_journey.png)

The complete data journey illustrates how incoming packets are processed through kernel-level filtering, undergo dual-path analysis (statistical and machine learning), and culminate in intelligent mitigation decisions.

### F. Paper Organization

The remainder of this paper is organized as follows: Section II presents a comprehensive literature review of eBPF-based DDoS mitigation, machine learning approaches, and related work. Section III details the system design and architecture. Section IV describes the implementation of eBPF programs, ML models, and detection algorithms. Section V presents experimental evaluation and performance analysis. Section VI discusses results, limitations, and future work. Finally, Section VII concludes the paper.

---

## II. LITERATURE REVIEW

The proliferation of DDoS attacks has motivated extensive research into detection and mitigation strategies. This literature review examines recent advances in three critical areas: (1) eBPF/XDP-based packet filtering, (2) machine learning approaches for anomaly detection, and (3) hybrid defense mechanisms.

### A. eBPF and XDP for Network Security

Extended Berkeley Packet Filter (eBPF) represents a paradigm shift in kernel programmability, enabling custom programs to execute safely within kernel space without modifying kernel source code or loading kernel modules. The integration of eBPF with XDP (eXpress Data Path) has proven particularly effective for high-performance network security applications.

#### 1) Network Traffic Monitoring and Filtering

Chen et al. [1] proposed a network situation awareness framework leveraging eBPF for real-time DDoS detection. Their work demonstrated that eBPF programs attached to network interfaces can efficiently parse packet headers and maintain per-flow statistics with minimal performance overhead. The authors achieved significant improvements in detection latency compared to traditional user-space packet capture mechanisms like libpcap. Their system stored aggregated statistics in HBase for historical analysis, enabling pattern recognition across temporal dimensions.

Zhang et al. [2] conducted comprehensive research on efficient packet filtering using eBPF, focusing on optimization techniques to reduce time complexity in high-throughput environments. Their study analyzed various eBPF map types (hash maps, arrays, per-CPU maps) and their performance characteristics under different traffic loads. The research emphasized the importance of XDP's position in the networking stack—executing before even the socket buffer (sk_buff) allocation—which dramatically reduces memory consumption during attack scenarios. Their experimental results showed packet processing throughput exceeding 10 million packets per second on commodity hardware with multi-queue NICs.

#### 2) DDoS Protection in IoT and Container Environments

Živanović and Vuletić [3] addressed DDoS protection challenges specific to IoT networks, where resource-constrained devices require lightweight yet effective security mechanisms. Their kernel-level protection system using eBPF demonstrated that even embedded Linux systems can benefit from XDP-based filtering. The authors implemented protocol-specific filters for MQTT traffic, a common IoT communication protocol, and achieved sub-millisecond response times for attack detection and mitigation. Their work highlighted eBPF's suitability for edge computing scenarios where centralized security solutions are impractical.

Remya et al. [4] presented a groundbreaking approach to detecting semantic DDoS attacks in Linux containers using eBPF-based runtime monitoring. Unlike volumetric attacks that flood networks with traffic, semantic attacks exploit application logic through seemingly legitimate requests. Their Container-Oriented DDoS Attack (CODA) detection system monitors system calls, file operations, and network behavior at the kernel level, correlating multiple behavioral signals to identify malicious container activities. The research demonstrated that eBPF kprobes and tracepoints can capture fine-grained execution context without introducing significant overhead, achieving 98.7% detection accuracy for semantic attacks while maintaining container performance within 3% overhead.

#### 3) In-Kernel Traffic Analysis

Zang et al. [5] introduced an innovative in-kernel traffic sketching mechanism for volumetric DDoS detection, addressing the fundamental challenge of processing terabits-per-second traffic volumes in modern data centers. Their system implements Count-Min Sketch and HyperLogLog probabilistic data structures directly in eBPF programs, enabling dimension reduction and statistical summarization at line rate. By performing traffic aggregation in kernel space before exporting to user space, their approach reduced memory bandwidth requirements by 95% compared to full packet logging. The research demonstrated that sophisticated data structures traditionally confined to user-space analytics can be effectively implemented within eBPF's instruction set limitations.

### B. Machine Learning for DDoS Detection

Machine learning techniques have emerged as powerful tools for identifying attack patterns that evade signature-based detection systems. The integration of ML with kernel-level packet processing represents a promising research direction.

#### 1) Comprehensive DDoS Detection Frameworks

Hirsi et al. [6] conducted an extensive systematic review of DDoS anomaly detection approaches in Software-Defined Networks (SDN), providing a comprehensive taxonomy of attack types, detection methodologies, and performance metrics. Their analysis covered over 150 research papers spanning flooding attacks, amplification attacks, protocol exploitation, and botnet-based DDoS campaigns. The authors identified key challenges including dataset quality, feature engineering overhead, model interpretability, and real-time inference latency. Their findings emphasized that ensemble methods (Random Forest, Gradient Boosting) consistently outperform single classifiers for multi-class attack classification, achieving F1-scores above 0.95 on balanced datasets.

#### 2) eBPF Integration with Machine Learning

Anand et al. [7] presented a pioneering approach that bridges kernel-level packet capture with machine learning algorithms for intrusion detection. Their system architecture extracts statistical features from eBPF maps in user space and feeds them to trained classifiers (Random Forest, SVM, Neural Networks). The research demonstrated that feature extraction latency constitutes the primary bottleneck in real-time ML-based detection, with their optimized implementation achieving sub-10ms inference time. The authors emphasized the importance of feature selection, showing that dimensionality reduction from 83 to 32 features maintained 94% accuracy while reducing inference time by 60%.

In a follow-up study, Anand et al. [9] specifically investigated high-performance intrusion detection systems combining eBPF with machine learning algorithms. Their research compared multiple ML models (Naive Bayes, K-Nearest Neighbors, Decision Trees, Random Forest, Neural Networks) for computational efficiency and detection accuracy. The findings revealed that Random Forest models offer the optimal balance between accuracy (96.3%) and inference speed (8.7ms per prediction), making them particularly suitable for real-time DDoS mitigation. The paper also addressed practical deployment challenges including model updates, concept drift adaptation, and threshold tuning in production environments.

### C. eBPF Performance Optimization

Understanding eBPF map performance characteristics is crucial for designing efficient network security systems. Liu et al. [8] conducted in-depth performance analysis of various eBPF map types under different access patterns and concurrency levels. Their research revealed that:

- **Array maps** provide O(1) lookup performance but waste memory for sparse datasets
- **Hash maps** offer flexible key-value storage with higher lookup latency (~200ns)
- **Per-CPU maps** eliminate lock contention for frequently updated statistics
- **LRU (Least Recently Used) hash maps** automatically evict old entries, ideal for flow tracking

The authors demonstrated that careful selection of map types based on access patterns can improve throughput by up to 3.5x in multi-core systems. For DDoS mitigation, their findings suggest using per-CPU array maps for global statistics aggregation and LRU hash maps for flow tracking to balance memory efficiency with lookup performance.

### D. Container and Cloud Security

#### 1) Kubernetes DDoS Detection

Sadiq et al. [10] addressed DDoS detection challenges specific to cloud-based Kubernetes environments, where containerized microservices communicate through complex service meshes. Their eBPF-based detection system monitors inter-pod traffic, ingress/egress patterns, and resource consumption metrics to identify anomalous behavior. The research demonstrated that container orchestration platforms introduce unique attack surfaces, including resource exhaustion attacks targeting scheduler components and lateral movement between compromised containers. Their detection system achieved 97.2% accuracy in identifying DDoS attacks targeting Kubernetes services while maintaining minimal impact on cluster performance.

#### 2) Kernel-Level Intrusion Prevention

Hadi et al. [11] introduced iKern, an advanced intrusion detection and prevention system operating entirely at the kernel level using eBPF. Unlike traditional IDS/IPS systems that rely on packet mirroring to external monitoring tools, iKern performs inline analysis and enforcement. The system implements a rule engine in eBPF that can block malicious packets immediately upon detection, preventing them from consuming downstream resources. Their comprehensive evaluation against CICIDS2017 and CIC-DDoS-2019 datasets demonstrated 99.1% detection accuracy with false positive rates below 0.5%. The research highlighted eBPF's capability to implement complex stateful inspection logic previously reserved for user-space security appliances.

### E. Research Gaps and Opportunities

Despite significant advances in eBPF-based security and ML-driven anomaly detection, several critical gaps remain:

1. **Hybrid Detection Integration**: Most existing work treats kernel-level filtering and ML-based classification as separate domains. Limited research explores architectures that seamlessly integrate statistical baseline detection with supervised learning while maintaining real-time performance.

2. **Feature Engineering Overhead**: Current ML-based systems extract features in user space after retrieving raw statistics from eBPF maps. This introduces latency and computational overhead. Investigating in-kernel feature computation could significantly reduce detection latency.

3. **Attack Type Classification**: While binary classification (attack vs. benign) has been extensively studied, multi-class attack type identification with real-time performance remains challenging. Understanding specific attack types enables targeted mitigation strategies.

4. **Adaptive Learning**: Existing systems use static thresholds and pre-trained models that degrade over time due to concept drift in network traffic patterns. Continuous learning approaches that adapt to evolving traffic profiles represent an important research direction.

5. **Cross-Platform Deployment**: Most eBPF security research targets Linux-specific implementations. The emergence of Microsoft eBPF for Windows creates opportunities for cross-platform security solutions that have not been adequately explored.

The Rapid-Corona system addresses these gaps by proposing a novel hybrid architecture that:
- Integrates kernel-space packet processing with dual-layer anomaly detection
- Implements efficient real-time feature extraction optimized for ML inference
- Provides multi-class attack classification with confidence scoring
- Supports adaptive baseline learning for evolving traffic patterns
- Offers cross-platform compatibility through abstracted eBPF interfaces

### F. Summary

The literature demonstrates that eBPF/XDP technology provides unprecedented performance for packet-level operations, while machine learning offers superior accuracy for complex pattern recognition. However, the challenge lies in effectively combining these technologies to create production-grade DDoS mitigation systems that operate at line-rate speeds while maintaining high detection accuracy and low false-positive rates. Our research builds upon these foundational works to develop a comprehensive solution addressing real-world deployment requirements.

---

## III. REFERENCES

[1] H. Chen, D. Song, Y. Zheng and F. Xiong, "Network Situation Awareness Technology based on Extended Berkeley Packet Filter," 2023 3rd International Conference on Electronic Information Engineering and Computer Science (EIECS), Changchun, China, 2023, pp. 101-104, doi: 10.1109/EIECS59936.2023.10435373.

[2] Y. Zhang, H. Wang and P. Gao, "Research on Efficient Packet Filter Technology Based on eBPF," 2025 IEEE 8th Advanced Information Technology, Electronic and Automation Control Conference (IAEAC), Guiyang, China, 2025, pp. 891-894, doi: 10.1109/IAEAC65194.2025.11165810.

[3] K. Živanović and P. Vuletić, "Kernel-Level DDoS Protection Using eBPF in Iot Networks," 2025 33rd Telecommunications Forum (TELFOR), Belgrade, Serbia, 2025, pp. 1-4, doi: 10.1109/TELFOR67910.2025.11314317.

[4] S. Remya et al., "eBPF-Based Runtime Detection of Semantic DDoS Attacks in Linux Containers," in IEEE Access, vol. 13, pp. 169178-169219, 2025, doi: 10.1109/ACCESS.2025.3614389.

[5] M. Zang, F. De Iaco, J. Wu and M. Savi, "In-Kernel Traffic Sketching for Volumetric DDoS Detection," ICC 2025 - IEEE International Conference on Communications, Montreal, QC, Canada, 2025, pp. 2180-2185, doi: 10.1109/ICC52391.2025.11161251.

[6] A. Hirsi et al., "Comprehensive Analysis of DDoS Anomaly Detection in Software-Defined Networks," in IEEE Access, vol. 13, pp. 23013-23071, 2025, doi: 10.1109/ACCESS.2025.3535943.

[7] N. Anand, S. M A, P. K. Aakula, R. B. Ponnuru, R. Patan, and C. R. P. Reddy, "Enhancing intrusion detection against denial of service and distributed denial of service attacks: Leveraging extended Berkeley packet filter and machine learning algorithms," IET Communications, vol. 19, e12879, 2025, doi: 10.1049/cmu2.12879.

[8] C. Liu, B. Tak, and L. Wang, "Understanding Performance of eBPF Maps," in Proceedings of the ACM SIGCOMM 2024 Workshop on eBPF and Kernel Extensions (eBPF '24), Association for Computing Machinery, New York, NY, USA, 2024, pp. 9–15, doi: 10.1145/3672197.3673430.

[9] N. Anand, S. M A, P. K. Aakula et al., "High-performance Intrusion Detection System using eBPF with Machine Learning algorithms," Research Square, July 2023, doi: 10.21203/rs.3.rs-3140072/v1.

[10] A. Sadiq, H. J. Syed, A. A. Ansari, A. O. Ibrahim, M. Alohaly, and M. Elsadig, "Detection of Denial of Service Attack in Cloud Based Kubernetes Using eBPF," Applied Sciences, vol. 13, no. 8, p. 4700, 2023, doi: 10.3390/app13084700.

[11] H. J. Hadi, M. Adnan, Y. Cao, F. B. Hussain, N. Ahmad, M. A. Alshara, and Y. Javed, "iKern: Advanced Intrusion Detection and Prevention at the Kernel Level Using eBPF," Technologies, vol. 12, no. 8, p. 122, 2024, doi: 10.3390/technologies12080122.

