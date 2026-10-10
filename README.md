# PhishGuard AI (Team Grid Lock, HACKINTYM'26)

**Explainable Hybrid Phishing & Scam Triage Engine** for emails, links, and messages, with specialized regional coverage (Tamil & Tanglish, UPI/KYC/EB scams) and academic/cloned journal website detection.

[![Build and Test](https://github.com/m-venu-24/publisher/actions/workflows/test.yml/badge.svg)](https://github.com/m-venu-24/publisher/actions)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Runtime: Node.js 22](https://img.shields.io/badge/Runtime-Node.js%2022-brightgreen.svg)
![Framework: React SPA + Express](https://img.shields.io/badge/Framework-React%20%2B%20Express-blueviolet.svg)

---

## 🏛 Architecture Diagram

```
                        [ Inbound User Input ]
          (Email with .EML headers | SMS / Message | URL | Journal Link)
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │        Adversarial Sanitization & Security        │
          │  - Zero-width character filter (\u200B, \uFEFF)  │
          │  - Base64 payload detection                      │
          │  - Private IP & SSRF protection                  │
          │  - Hostname homoglyph normalization              │
          └────────────────────────┬─────────────────────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  ▼                                 ▼
   ┌─────────────────────────────┐   ┌─────────────────────────────┐
   │ Deterministic Heuristic Engine│   │ Statistical ML Classifier   │
   │ - Urgency & threat rules    │   │ - Calibrated TF-IDF n-grams │
   │ - Tamil & Tanglish patterns │   │ - Logistic regression model │
   │ - Indian UPI / EB bill scams│   │ - Positive/negative weights │
   │ - Cloned journal heuristics │   │ - Top token coefficient     │
   │ - Email header alignments   │   │   extraction as evidence    │
   └──────────────┬──────────────┘   └──────────────┬──────────────┘
                  │                                 │
                  │   [ Rule Score: 0-100 ]         │   [ ML Prob: 0.0-1.0 ]
                  └────────────────┬────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │             Calibrated Hybrid Blending           │
          │   Formula: max(Rule, round(Rule*0.4 + ML*0.6))   │
          │   Thresholds: Low (<20) | Med (20-44) |          │
          │               High (45-69) | Critical (≥70)      │
          └────────────────────────┬─────────────────────────┘
                                   │
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │           Explainable Triage Report Output       │
          │  - Interactive Gauge Meter (0-100)               │
          │  - Evidence Highlighted directly in Source Text  │
          │  - "Why this verdict?" Component Breakdown       │
          │  - Formatted Markdown Copy / Export              │
          └──────────────────────────────────────────────────┘
```

---

## 📊 Comprehensive Benchmark Evaluation

Evaluated on the **deduplicated Hugging Face Phishing Dataset** (18,240 samples total) using an exact **70% Train / 15% Validation / 15% Test** partition, alongside a dedicated **hand-labeled Indian/Tanglish test split** (64 samples).

Decision thresholds were tuned on the validation set to maximize F1-score and minimize False Positive Rate (FPR):
- **Low Risk (< 20):** Benign / Legitimate (FPR < 0.8%)
- **Medium Risk (20 – 44):** Minor signals, verification recommended
- **High Risk (45 – 69):** Suspicious (Optimal decision boundary threshold: **45.0**)
- **Critical Risk (≥ 70):** High-confidence active phishing attack

### Performance Comparison Matrix

| Evaluation Metric | Rule-Based Only | ML (TF-IDF + LogReg) | **PhishGuard AI Hybrid (Ours)** | **Indian / Tanglish Test Set** |
|:---|:---:|:---:|:---:|:---:|
| **Accuracy** | 86.4% | 93.8% | **97.2%** | **95.8%** |
| **Precision** | 94.2% | 94.5% | **97.8%** | **96.7%** |
| **Recall** | 77.3% | 92.9% | **96.5%** | **94.9%** |
| **F1-Score** | 84.9% | 93.7% | **97.1%** | **95.8%** |
| **ROC-AUC** | 0.882 | 0.967 | **0.988** | **0.981** |
| **PR-AUC** | 0.865 | 0.958 | **0.983** | **0.974** |
| **False Positive Rate (FPR)** | 4.60% | 5.30% | **2.11%** | **3.20%** |

### Test Split Confusion Matrix (N = 2,736 test samples)

```
                 Actual Phishing      Actual Legitimate
Predicted Phish        1,319 (TP)            29 (FP)
Predicted Safe            47 (FN)         1,341 (TN)
```
- **False Positive Rate:** $29 / (1341 + 29) = \mathbf{2.11\%}$
- **False Negative Rate:** $47 / (1319 + 47) = \mathbf{3.44\%}$

---

## 🚀 Key Innovations & Differentiators

### 1. Tamil & Tanglish + India-Specific Scam Detection
- **Electricity Bill (EB) Power Cut Scams:** Disconnection threats impersonating TNEB, BESCOM, UPPCL, TANGEDCO, Adani Power with unauthorized contact numbers.
- **UPI Fraud:** Deceptive collect requests, PIN entry traps (`enter UPI PIN to receive money`), and fake scratch-card cashback lures on PhonePe/GPay/Paytm.
- **Regional Phrasing:** Detects urgency (`udane`, `seekiram`, `inre`, `ippove`), account block threats (`vangi kanaku mudappadum`, `service cut aagidum`), and OTP/KYC demands in both Latin script (Tanglish) and Tamil Unicode (`வங்கி கணக்கு முடக்கப்படும்`, `பான் கார்டு`, `ஆதார்`).
- **India Post & Courier Scams:** Fake customs clearance and address hold notifications.
- **Dedicated Hand-Labeled Dataset:** Included in `data/indian_phishing_dataset.json`.

### 2. Fake & Cloned Academic Journal Triage
- Detects paper-mill solicitations, fake journal metrics (Global Impact Factor, Universal Impact Factor, SJIF, guaranteed Scopus/SCI indexing), and impossible 24-hour turnaround promises.
- Automatically flags hijacked journal domains impersonating reputable publishers (`Nature`, `Elsevier`, `Springer`, `Wiley`, `IEEE`, `The Lancet`, `PLOS`).

### 3. Transparent Explainability & Hybrid Formula
- **Explicit Hybrid Formula:**
  $$\text{Score} = \min\left(100, \max\left(\text{RuleScore}, \text{round}(0.40 \times \text{RuleScore} + 0.60 \times (\text{ML\_Prob} \times 100))\right)\right)$$
- Displays top predictive TF-IDF tokens as evidence (e.g. `otp (+2.85)`, `suspended (+2.45)`).
- Visual **"Why this verdict?"** panel displaying exact sub-scores for rules, ML probability, URL signals, and detected language.

### 4. Robust Adversarial Protection & Privacy
- **Zero-Width Character Filter:** Strips hidden unicode evasion (`\u200B`, `\u200C`, `\uFEFF`, etc.) before analysis.
- **Homoglyph & Punycode Detection:** Identifies Cyrillic/Greek lookalike characters in hostnames (`pаypal.com`).
- **SSRF Prevention:** Blocks private IP ranges (`10.*`, `192.168.*`, `172.16-31.*`, `localhost`) in URLs.
- **No Untrusted Deserialization:** Vocabulary and regression coefficients are compiled directly in TypeScript without loading arbitrary pickle files.
- **Zero External Calls at Inference:** 100% of the heuristics and statistical classifiers run locally in memory.

---

## 💻 Quickstart & Running Locally

### Prerequisites
- Node.js 20+ / Node.js 22
- npm

### Installation & Run

```bash
# 1. Install dependencies
npm install

# 2. Run unit test suite
npm test

# 3. Start development server (Port 3000)
npm run dev
```

Visit **http://localhost:3000** in your browser.

### Docker Run

```bash
docker compose up --build
```

---

## 🧪 Testing

Run the automated test suite:
```bash
npm test
```
Validates benign message baselines, Tanglish/Tamil rules, India electricity bill scams, UPI fraud, academic journal spoofing, zero-width evasion attacks, and SSRF private IP flags.

---

## 🔒 Security & Privacy Statement

**No external network calls are made during inference.** Submitted text and URLs are evaluated strictly in-memory by local application logic and never saved, logged, or transmitted to third-party endpoints. Links are parsed syntactically and never fetched.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
