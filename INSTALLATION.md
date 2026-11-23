# Installation & Setup Guide — DPI & Packet Analyzer

**Platform Version:** `v5.5.0-FINAL`  
**Supported Platforms:** macOS (Apple Silicon arm64, Intel x86_64), Linux (x86_64, aarch64)  

---

## 1. Prerequisites

### 1.1 C++ Compiler & Build Toolchain
- **Compiler:** Clang 11+ (Apple Clang 14+) or GCC 9+ with full **C++17** support.
- **Build System:** GNU `make` 3.81+.
- **Standard Libraries:** ISO C++ Standard Library, POSIX threads (`-lpthread`).
- *Note:* No third-party C/C++ libraries are required. Libpcap is NOT required (the engine contains an internal standalone PCAP reader).

### 1.2 Python Environment
- **Python Version:** Python 3.8, 3.9, 3.10, 3.11, 3.12, or 3.13.
- **Package Manager:** `pip`

---

## 2. Step-by-Step Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/example/Packet_analyzer-main.git
cd Packet_analyzer-main
```

### Step 2: Install Python Dependencies
Install the required packages pinned in `requirements.txt`:
```bash
pip install -r requirements.txt
```
The dependencies are strictly minimal:
- `numpy >= 1.24.0`
- `scikit-learn >= 1.3.0`
- `joblib >= 1.3.0`

### Step 3: Build the C++ Engine Binaries
Compile the production binary:
```bash
make clean && make
```
This builds:
- `bin/dpi_engine` — Main production DPI command-line executable.
- `bin/test_runner` — Automated test harness (180 C++ tests).

---

## 3. Verification & Sanitizer Builds

Verify that your compiler and environment run the test suite cleanly:

```bash
# Standard test suite execution
make test

# AddressSanitizer (memory safety, bounds, leak detection)
make test_asan

# UndefinedBehaviorSanitizer (overflows, alignment, pointer validation)
make test_ubsan

# ThreadSanitizer (data races, concurrency verification)
make test_tsan

# Run Python AI & API test suite (54 tests)
python3 -m unittest discover tests/ "test_*.py"
```
**Expected Outcome:** 234 / 234 tests passing with zero errors and zero memory leaks.

---

## 4. Launching the System

### Run Analysis on a PCAP
```bash
./bin/dpi_engine test_dpi.pcap data/current_session/forwarded_traffic.pcap \
  --analyze-all data/current_session \
  --detect \
  --incidents \
  --signatures \
  --threat-intelligence \
  --rules-dir config/signatures \
  --threat-intel-dir config/threat_intel
```

### Start the REST API & Web Dashboard
```bash
python3 server/api_server.py --port 8080 --data-dir data/current_session
```
Access the offline dashboard at: **`http://localhost:8080`**
