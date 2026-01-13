                              ███████╗██╗   ██╗██╗███████╗███████╗██████╗  ██████╗ 
                              ██╔════╝██║   ██║██║╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
                              ███████╗██║   ██║██║  ███╔╝ █████╗  ██████╔╝██║   ██║
                              ╚════██║██║   ██║██║ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
                              ███████║╚██████╔╝██║███████╗███████╗██║  ██║╚██████╔╝
                              ╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
> **Static Analysis Engine for Sui Move**

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg?style=for-the-badge)](https://github.com/suizero/suizero)
[![Protection](https://img.shields.io/badge/security-enterprise-crimson.svg?style=for-the-badge)](https://sui.io)
[![Accuracy](https://img.shields.io/badge/accuracy-80%25-success.svg?style=for-the-badge)](docs/VALIDATION_REPORT.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)](LICENSE)


---
## ⚡ Overview

**SUIZERO** 
is a high-signal security analysis engine purpose-built for the Sui Move ecosystem. It focuses on detecting real, exploitable vulnerabilities in Sui smart contracts by analyzing compiled bytecode and semantic execution patterns—not surface-level linting.
SUIZERO is designed for environments where shared objects, capabilities, and economic invariants create attack surfaces that traditional scanners miss.


---
### 🔬 Deep Inspection Technology
SUIZERO doesn't just read code; it simulates execution paths to find:

*   **🕵️ Phantom Authorization**: Parameters that *look* like security checks but are actually ignored.
*   **⏳ Temporal Bugs**: Race conditions between object inspection and mutation.
*   **⚖️ Economic Invariants**: Mathematical asymmetries in deposit/withdraw logic.

---
## Installation Requirements

### System Dependencies

1. **Rust Toolchain** (required)
   - Install Rust via [rustup](https://rustup.rs/):
     ```bash
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
   - Or via your package manager:
     ```bash
     # Ubuntu/Debian
     sudo apt install rustc cargo

     # macOS (with Homebrew)
     brew install rust
     ```

2. **Git** (required)
   - For cloning the repository and fetching dependencies
   ```bash
   # Ubuntu/Debian
   sudo apt install git

   # macOS (with Homebrew)
   brew install git

   # Check installation
   git --version
   ```

3. **Build Tools** (required)
   - For compiling Rust dependencies
   ```bash
   # Ubuntu/Debian
   sudo apt install build-essential

   # macOS
   xcode-select --install

   # CentOS/RHEL/Fedora
   sudo yum groupinstall "Development Tools"
   ```

### Optional Dependencies

1. **SUI CLI** (optional, for enhanced functionality)
   - Install the SUI CLI for additional integration:
   ```bash
   # Follow official SUI installation guide
   # https://docs.sui.io/devnet/build/install
   ```


## 📦 Installation 

```bash
git clone https://github.com/kaveyjoe/SUIZERO.git
cd SUIZERO  
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

# 📊 Generate Detailed HTML Report
./target/release/suizero analyze ./build --format html > report.html

# 🔍 Specify Severity Threshold (only show critical and high issues)
./target/release/suizero analyze ./build --min-severity critical

# 📈 Verbose Output with Detailed Analysis
./target/release/suizero analyze ./build --verbose

# 📁 Analyze Specific Module
./target/release/suizero analyze ./build/your_package/bytecode_modules

# 📋 Generate Summary Report
./target/release/suizero analyze ./build --format summary
```


### 4. Example Analysis Workflow
```bash
# Clone and build SUIZERO
git clone https://github.com/kaveyjoe/SUIZERO.git
cd SUIZERO
cargo build --release --bin suizero

# Navigate to your Sui Move project
cd /path/to/your/sui/project

# Build your Move contracts
sui move build

# Run security analysis
../SUIZERO/target/release/suizero analyze ./build --format markdown > security_report.md

# Review the findings in security_report.md
```



## 📚 Documentation

*   [🏗️ System Architecture](docs/DOCUMENTATION.md) - How it works.
*   [📜 Validation Report](docs/VALIDATION_REPORT.md) - Proof of accuracy.
*   [🧪 Test Examples](examples/) - Try it yourself.
*   [📊 Sample Analysis Report](docs/suizero_analysis_results.md) - Example output from analyzing vulnerable contracts.

---

## 🤝 Acknowledgements

Special thanks to the **Sui Foundation** and **Mysten Labs** for creating Move, a language that makes formal verification possible.

---

<div align="center">
  <sub>Built with ❤️ by KAVEYJOE
</div>
