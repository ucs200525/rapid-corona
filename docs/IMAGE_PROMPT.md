# Image Generation Prompt for DDoS Mitigation System Architecture

**Concept:** A modern, high-tech system architecture diagram illustrating the data flow in a hybrid eBPF/XDP and Machine Learning DDoS mitigation system. The style should be clean, flat 2D schematic with neon blue and purple accents on a dark background.

**Key Components & Flow:**

1.  **Network Interface (NIC)**:
    -   *Visual*: A network port or physical hardware icon.
    -   *Label*: "Network Interface (NIC)"
    -   *Action*: Red arrows labeled "Incoming Traffic" entering this block.

2.  **Kernel Space (eBPF/XDP Filter)**:
    -   *Visual*: A shield or filter icon residing inside a "Kernel Space" boundary.
    -   *Label*: "eBPF/XDP Filter"
    -   *Action*: This component splits traffic into two paths:
        -   **Dropped Packets**: Red arrow pointing to a trash/discard icon.
        -   **Passed Packets**: Green arrow flowing upwards to Userspace.

3.  **Blacklist Map (eBPF Map)**:
    -   *Visual*: A database table or shared memory block icon, connected to the XDP Filter.
    -   *Label*: "Shared Blacklist Map"
    -   *Action*: Two-way sync arrows. The XDP Filter reads from it to block, and the Userspace Controller writes to it.

4.  **Userspace Controller (Python)**:
    -   *Visual*: A central processing block/gear icon.
    -   *Label*: "Userspace Controller (Python)"
    -   *Action*: Receives stats from Kernel Space and feeds data to the ML component.

5.  **Machine Learning Classifier**:
    -   *Visual*: A brain or neural network node icon.
    -   *Label*: "ML Anomaly Detector (Random Forest)"
    -   *Action*: Analyzes traffic patterns and sends "Block Decisions" (updates) to the Blacklist Map.

6.  **Real-Time Dashboard**:
    -   *Visual*: A monitor screen or web browser UI icon.
    -   *Label*: "Web Dashboard (Flask)"
    -   *Action*: Connected to the Userspace Controller to display graphs.

**Aesthetic Guidelines:**
-   **Background**: Dark, technical grid or solid dark grey.
-   **Colors**: Neon Cyan (Data Flow), Red (Threats/Drops), Purple (ML/AI), Green (Safe Traffic).
-   **Style**: Abstract technical diagram, avoiding specific software screenshot looks. Focus on the logical flow.
