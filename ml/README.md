# Machine Learning Module --- Anomaly Detection

Artificial Intelligence-based anomaly detection module integrated into the SIEM. This module uses the **Isolation Forest** algorithm from scikit-learn to identify suspicious HTTP requests that evade signature-based (RegEx) detectors.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Module Architecture](#module-architecture)
3. [Feature Extraction](#feature-extraction)
4. [Model Training](#model-training)
5. [Prediction and Scoring](#prediction-and-scoring)
6. [Module Files](#module-files)
7. [Usage](#usage)
8. [Performance](#performance)

---

## How It Works

The approach relies on unsupervised learning: the model is trained exclusively on **normal** (legitimate) HTTP traffic. Once trained, it can detect requests that deviate significantly from this normal profile, classifying them as anomalies.

This principle enables detection of :
- Obfuscated attacks that bypass classic RegEx patterns
- Zero-day attacks with no known signature
- High-entropy payloads (unusual encodings, binary data)
- Requests with abnormal JSON structures (prototype pollution, injections)

---

## Module Architecture

```
HTTP Log Line
       |
       v
+------------------------+
|  Extract 13 Features   |   anomaly_detector.py :: extract_features()
+------------------------+
       |
       v
+------------------------+
|  Normalization         |
|  StandardScaler        |   scaler.pkl
+------------------------+
       |
       v
+------------------------+
|  Isolation Forest      |
|  (300 estimators)      |   anomaly_model.pkl
+------------------------+
       |
       v
+------------------------+
|  Calibration           |
|  Sigmoid + Boost       |   Score between 0.0 and 1.0
+------------------------+
       |
       v
   Result:
   (is_anomaly, score)
```

---

## Feature Extraction

Each log line is transformed into a vector of **13 numerical features**:

| Index | Feature                      | Description                                                       | Weight |
|:-----:|------------------------------|-------------------------------------------------------------------|:------:|
|   0   | Line length                  | Total character count of the log line                             |  x1    |
|   1   | URL length                   | Size of the URL/path portion of the request                       |  x1    |
|   2   | Parameter count              | Count of `=` and `&` characters (URL and body parameters)         |  x1    |
|   3   | Special characters           | Count of `< > ' ; ( ) [ ] * | $ \` \ & ! %`                      |  x6    |
|   4   | SQL patterns                 | Matches against RegEx patterns from `detectors/sqli.py`           |  x8    |
|   5   | XSS patterns                 | Matches against RegEx patterns from `detectors/xss.py`            |  x8    |
|   6   | Path Traversal patterns      | Matches against `detectors/traversal.py`                          |  x6    |
|   7   | RCE/Shell patterns           | Matches against `detectors/os_injection.py`                       |  x12   |
|   8   | NoSQL patterns               | Matches against `detectors/nosql.py`                              |  x8    |
|   9   | Shannon entropy              | Measure of string complexity/randomness                           |  x25   |
|  10   | Non-ASCII ratio              | Proportion of non-ASCII characters and hex-encoded sequences      | x150   |
|  11   | Digit density                | Proportion of numeric characters in the line                      | x100   |
|  12   | Control characters           | Count of control characters (0x00-0x1F)                           |  x20   |

The weights applied to each feature balance their relative importance within the model.

---

## Model Training

The `train.py` script generates synthetic training data and trains the model.

### Generated Data

| Type                    | Volume  | Description                                                    |
|-------------------------|--------:|----------------------------------------------------------------|
| Normal logs (training)  |  5,000  | Diverse legitimate HTTP requests (API, static, pages)          |
| Normal logs (validation)|    500  | Validation set for measuring false positives                   |
| Attack logs (validation)|    500  | Diverse attacks for measuring true positives                   |

### Attack Types Covered During Training

- SQL Injection (classic and advanced)
- Cross-Site Scripting (XSS)
- NoSQL Injection (MongoDB)
- IDOR / Broken Access Control
- Server-Side Request Forgery (SSRF)
- Prototype Pollution
- Path Traversal
- Remote Code Execution (RCE)
- Sensitive file access
- Zero-day payloads (XXE, SSTI, deserialization)

### Model Parameters

| Parameter         | Value    | Description                                               |
|-------------------|----------|-----------------------------------------------------------|
| `n_estimators`    | 300      | Number of trees in the isolation forest                   |
| `contamination`   | 0.01     | Estimated proportion of anomalies in normal data          |
| `max_samples`     | auto     | Automatic sampling for each tree                          |
| `random_state`    | 42       | Seed for reproducibility                                  |

### Training Pipeline

1. Generate 5,000 normal HTTP logs (unified and Apache CLF formats)
2. Extract 13 features for each log
3. Normalize via `StandardScaler` (mean=0, std=1)
4. Train Isolation Forest on normalized data
5. Evaluate on validation sets (false positives and true positives)
6. Serialize the model (`anomaly_model.pkl`) and scaler (`scaler.pkl`)

---

## Prediction and Scoring

### Prediction Process

For each new log line:

1. Extract the 13-feature vector
2. Normalize using the pre-trained scaler
3. Predict with Isolation Forest (-1 = anomaly, +1 = normal)
4. Compute score via `decision_function` and sigmoid calibration

### Score Calibration

The raw Isolation Forest score is transformed into a value between 0 and 1 using a **sigmoid function**:

```
score = 1 / (1 + exp(decision_value * 15))
```

- **Score close to 0**: normal traffic
- **Score close to 1**: strong anomaly

### Pattern Boost

If a critical pattern is detected by RegEx (SQL, XSS, Traversal, RCE, NoSQL), the score is automatically boosted to a minimum of **0.75**, ensuring that known attacks are never classified as normal by the ML engine.

### Decision Thresholds

| Threshold | Decision                                        |
|-----------|-------------------------------------------------|
| < 0.40    | Normal (displayed in green on the dashboard)    |
| 0.40-0.69 | Suspicious (displayed in orange)               |
| >= 0.70   | Confirmed anomaly (displayed in red, alert)    |

---

## Module Files

```
ml/
|-- __init__.py            # Module import
|-- anomaly_detector.py    # AnomalyDetector class (extraction, training, prediction)
|-- train.py               # Training script with synthetic data generation
|-- anomaly_model.pkl      # Serialized Isolation Forest model (~4.5 MB, pre-trained)
|-- scaler.pkl             # Serialized StandardScaler
```

---

## Usage

### Pre-trained Model

The model ships **pre-trained**. The dashboard (`dashboard_gui.py`) automatically loads `anomaly_model.pkl` and `scaler.pkl` at startup. No manual training step is required to use the SIEM.

### Retrain the Model (Optional)

If you wish to retrain the model with updated data or modified parameters:

```bash
python ml/train.py
```

The script displays a quality evaluation at the end of execution:
- **EXCELLENT**: True Positives > 95% and False Positives < 5%
- **GOOD**: True Positives > 80% and False Positives < 10%
- **NEEDS IMPROVEMENT**: below these thresholds

### Use the Detector in Code

```python
from ml.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()

# Predict on a log line
is_anomaly, score = detector.predict("2026-02-18T12:00:00Z  45.33.1.1  GET /api/search?q=' OR 1=1 --  200  10ms")

print(f"Anomaly: {is_anomaly}, Score: {score:.2f}")
```

### Integration with the SIEM

The dashboard (`dashboard_gui.py`) loads the model automatically at startup and applies ML prediction to every decrypted log line, alongside the signature-based detectors.

---

## Performance

Typical performance after training:

| Metric              | Expected Value |
|---------------------|:--------------:|
| True Positives (TP) |     > 95%      |
| False Positives (FP)|     < 5%       |
| Average normal score |    < 0.10     |
| Average attack score |    > 0.70     |

Performance may vary depending on the training data composition and the `contamination` parameter.
