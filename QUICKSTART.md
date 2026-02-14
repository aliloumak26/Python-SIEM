# 🚀 Quick Start Guide - Python SIEM

Welcome to the Python SIEM project! This guide will help you set up the environment, verify the installation, and understand the project workflow.

## 📋 Prerequisites

- **Python 3.10+** installed on your system.
- **Git** (optional, for cloning).

## 🛠️ Installation

1.  **Clone or Download the Repository**
    ```bash
    git clone <repository_url>
    # or download ZIP and extract
    cd Python-SIEM
    ```

2.  **Install Dependencies**
    It is recommended to use a virtual environment.
    ```bash
    # Create virtual environment
    python -m venv venv
    
    # Activate (Windows)
    .\venv\Scripts\activate
    
    # Activate (Linux/Mac)
    source venv/bin/activate
    
    # Install packages
    pip install -r requirements.txt
    ```

## ⚙️ Initialization

Before running the dashboard, you need to train the Machine Learning model for anomaly detection.

```bash
python ml/train.py
```
*You should see output indicating the model has been trained and saved.*

## 🖥️ Running the Application

The project has two components: the dashboard and the attack generator.

### 1. Start the Dashboard (Main Interface)
Opens the real-time monitoring interface.
```bash
python dashboard_gui.py
```

### 2. Generate Simulated Traffic (In a separate terminal)
To see the SIEM in action, you need network traffic. This script simulates various attacks (SQLi, XSS, Brute Force).
```bash
python attacks_generator.py
```

## 🔄 Project Workflow

Here is how the data flows through the system:

1.  **Traffic Generation**: `attacks_generator.py` creates fake network logs and "sends" them to the system.
2.  **Detection Layer**:
    *   **Signature-based**: Detectors in `detectors/` (SQLi, XSS, etc.) analyze payloads against known patterns.
    *   **Behavior-based**: `ml/anomaly_detector.py` uses Isolation Forest to flag unusual traffic volume or patterns.
3.  **Core Processing**:
    *   `core/engine.py` orchestrates the analysis.
    *   `core/alert_manager.py` assesses severity and creates alerts.
    *   `core/database.py` saves logs and alerts to `siem.db`.
4.  **Visualization**:
    *   `dashboard_gui.py` reads from the database and updates charts/tables in real-time.

## 🐛 Troubleshooting

-   **Missing Dependencies**: Ensure you activated the venv before running scripts.
-   **Database Locks**: If `siem.db` is locked, ensure no other python processes are holding it open improperly (though the code manages concurrency).
-   **GeoIP Errors**: The project uses `geoip2`. Ensure you have an internet connection or the appropriate database files if running offline (MaxMind GeoLite2).
