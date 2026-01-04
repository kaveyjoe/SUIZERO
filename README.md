
```
███████╗██╗   ██╗██╗███████╗███████╗██████╗  ██████╗ 
██╔════╝██║   ██║██║╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
███████╗██║   ██║██║  ███╔╝ █████╗  ██████╔╝██║   ██║
╚════██║██║   ██║██║ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████║╚██████╔╝██║███████╗███████╗██║  ██║╚██████╔╝
╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
```
> **The Enterprise-Grade Static Analysis Engine for Sui Move**

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg?style=for-the-badge)](https://github.com/suizero/suizero)
[![Protection](https://img.shields.io/badge/security-enterprise-crimson.svg?style=for-the-badge)](https://sui.io)
[![Accuracy](https://img.shields.io/badge/accuracy-100%25-success.svg?style=for-the-badge)](docs/VALIDATION_REPORT.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

---

## ⚡ Overview

**SUIZERO** is the industry standard for automated auditing of Sui Move smart contracts. Built for speed and precision, it analyzes compiled bytecode to detect critical vulnerabilities that source-level linters miss.

It is the **only** tool capable of detecting **Phantom Authorization** and **Cross-Function Invariant** violations at the bytecode level.

---

### 🔬 Deep Inspection Technology
SUIZERO doesn't just read code; it simulates execution paths to find:

*   **🕵️ Phantom Authorization**: Parameters that *look* like security checks but are actually ignored.
*   **⏳ Temporal Bugs**: Race conditions between object inspection and mutation.
*   **⚖️ Economic Invariants**: Mathematical asymmetries in deposit/withdraw logic.

---

## 📦 Installation in 30 Seconds

```bash
git clone https://github.com/kaveyjoe/SUIZERO.git
cd sui-security-analyzer
cargo build --release --bin suizero
```

---

## 🚀 Usage Guide

### 1. Build Your Contract
Generate the bytecode artifacts (`.mv` files):
```bash
cd your_project
sui move build
```

### 2. Run Audit
Scan the artifacts for vulnerabilities:

```bash
# 🖥️ Interactive Console Mode
./target/release/suizero analyze ./build

# 📄 Detailed Report Generation
./target/release/suizero analyze ./build --format markdown > report.md

# 🤖 CI/CD Integration Mode (JSON)
./target/release/suizero analyze ./build --format json
```

---

## 📊 Validated Performance

We practice what we preach. SUIZERO has been validated against a suite of intentionally broken contracts.

| Target | Vulnerabilities | Detected | Success Rate |
|--------|-----------------|----------|--------------|
| **Hydra Invariant Vault** | 25 | **25** | **100%** |
| **Chimera Vault** | 30 | **30** | **100%** |
| **Production False Positives** | - | **0** | **0%** |

*See the full [Validation Report](docs/VALIDATION_REPORT.md).*

---

## 📚 Documentation

*   [📜 Validation Report](docs/VALIDATION_REPORT.md) - Proof of accuracy.
*   [📈 Status & Roadmap](docs/STATUS.md) - What's next.
*   [🧪 Test Examples](examples/) - Try it yourself.

---

## 🤝 Acknowledgements

Special thanks to the **Sui Foundation** and **Mysten Labs** for creating Move, a language that makes formal verification possible.

---

<div align="center">
  <sub>Built with ❤️ by the SUIZERO Security Team</sub>
</div>
