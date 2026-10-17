# 🛡️ QuantumShield Z (Bharat Edition)
### AI-Assisted Post-Quantum Migration Prioritizer | IBM Z Datathon 2026

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-FF4B4B.svg)](https://streamlit.io)
[![NIST PQC Finalized](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-success.svg)](https://csrc.nist.gov/pqc)
[![DPDP Act 2023](https://img.shields.io/badge/Compliance-DPDP%20Act%202023-orange.svg)](https://www.meity.gov.in)
[![IBM z16 Ready](https://img.shields.io/badge/IBM%20Z-z16%20CPACF%20%26%20CEX8S-purple.svg)](https://www.ibm.com/z)

> **"Harvest Now, Decrypt Later" (HNDL)** poses an immediate threat to long-lived sensitive citizen records and financial infrastructure. **QuantumShield Z** is a secure, login-protected, interactive web application that evaluates cryptographic asset inventories, quantifies statutory risk exposure under India's **DPDP Act 2023**, and sequences an explainable post-quantum migration roadmap aligned with the **National Quantum Mission (NQM 2030)** and **IBM z16 Mainframe** hardware architecture.

---

## 🌟 Key Platform Capabilities

- **⚡ IBM z16 Hardware Offload Hub**:
  - Models on-chip **IBM Telum CPACF** wire-speed SHA-3/SHAKE lattice hashing (zero context switches).
  - Models **Crypto Express 8S (CEX8S)** FIPS 140-3 Level 4 HSM key token management (`CSNBKTR2` JCL).
  - **MIPS Hardware Dividend Calculator**: Proves annual ₹ Crore compute cost savings by eliminating the 21.4% CPU penalty seen on commodity x86 servers.
  - Production-ready **RACF**, **ICSF**, and **PAGENT AT-TLS** hybrid TLS 1.3 configuration templates.

- **🔬 Peer-Reviewed Quantum Cryptanalysis Lab**:
  - Implements the **Gidney & Ekerå (2021)** Shor's algorithm qubit model ($Q_{\text{logical}} = 2n + 2$, Surface Code physical qubit scaling).
  - Mathematical modeling of **Grover's quadratic speedup** ($\mathcal{O}(\sqrt{N})$) proving why AES-256 retains 128-bit quantum security ($\sim 3.4 \times 10^{38}$ operations) while AES-128 is compromised.
  - Interactive **IBM Quantum Roadmap Timeline** (Flamingo $\rightarrow$ Starling $\rightarrow$ Kookaburra).

- **🇮🇳 Sovereign Indian DPI & Mainframe Workloads**:
  - 28 realistic synthetic workloads spanning **UIDAI Aadhaar**, **NPCI UPI**, **RBI RTGS Sysplex**, **SBI Core Banking**, **DigiLocker**, **ISRO Satellite Telemetry**, and **HDFC CICS Transactions**.
  - Quantifies financial liabilities under **DPDP Act 2023 Section 8(5)** (up to ₹250 Crore per incident) and IBM Cost of a Data Breach India benchmarks (₹19.5 Crore baseline).

- **🛡️ Strict Zero-Trust Application Security**:
  - Password hashing via memory-hard `hashlib.scrypt` with unique 16-byte random salts.
  - Storage encryption at rest with **AES-256-GCM** (fresh 12-byte nonces and GCM tag validation).
  - Constant-time verification (`hmac.compare_digest`) immune to timing side-channels.
  - Persistent 5-minute brute-force lockout after 5 failed attempts (zero user enumeration).
  - Server-side Role-Based Access Control (`admin` and `analyst`).

- **📑 Boardroom Executive Dossier & CycloneDX CBOM**:
  - Instant one-click export of formal **Boardroom Migration Dossiers (`.md`)** with CISO, DPO, and CTO sign-off blocks.
  - Standardized **CycloneDX Cryptographic Bill of Materials (CBOM v1.6)** JSON export.

---

## 🚀 Local Quick Start (Run in 2 Minutes)

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/quantum-shield-z.git
cd quantum-shield-z
```

### 2. Create and Activate a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the Platform
```bash
streamlit run app.py --server.address localhost --server.port 8501
```
Open **[http://localhost:8501](http://localhost:8501)** in your browser.

---

## 🌐 Deploy to GitHub & Streamlit Cloud (Free Live Hosting)

### Step 1: Push Code to GitHub
```bash
git init
git add .
git commit -m "feat: QuantumShield Z (Bharat Edition) for IBM Z Datathon 2026"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
git push -u origin main
```

### Step 2: One-Click Deploy on Streamlit Community Cloud
1. Go to **[share.streamlit.io](https://share.streamlit.io/)** and sign in with GitHub.
2. Click **"New app"**.
3. Select your repository: `YOUR_USERNAME/YOUR_REPOSITORY_NAME`.
4. Branch: `main`
5. Main file path: `app.py`
6. (Optional) In **Advanced settings**, set the environment secret:
   ```toml
   QUANTUMSHIELD_MASTER_KEY = "YOUR_BASE64_32_BYTE_KEY"
   ```
7. Click **Deploy!** Your app will be live on a public URL in 60 seconds.

---

## ⚖️ License & Datathon Disclaimer
Built for the **IBM Z Datathon 2026**. All asset datasets are synthetic benchmark workloads designed to demonstrate explainable cryptographic risk prioritization.
