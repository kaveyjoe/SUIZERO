                              ███████╗██╗   ██╗██╗███████╗███████╗██████╗  ██████╗ 
                              ██╔════╝██║   ██║██║╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
                              ███████╗██║   ██║██║  ███╔╝ █████╗  ██████╔╝██║   ██║
                              ╚════██║██║   ██║██║ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
                              ███████║╚██████╔╝██║███████╗███████╗██║  ██║╚██████╔╝
                              ╚══════╝ ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
> **Advanced Static Analysis Engine for Sui Move Smart Contracts**

[![Version](https://img.shields.io/badge/version-1.0.1-blue.svg?style=for-the-badge)](https://github.com/suizero/suizero)
[![Security Rating](https://img.shields.io/badge/security-A%2B-success.svg?style=for-the-badge)](https://sui.io)
[![Accuracy](https://img.shields.io/badge/accuracy-85%25-success.svg?style=for-the-badge)](docs/VALIDATION_REPORT.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-success.svg?style=for-the-badge)](https://github.com/suizero/suizero/actions)

---
## ⚡ Overview

**SUIZERO** is a cutting-edge security analysis engine purpose-built for the Sui Move ecosystem. It focuses on detecting real, exploitable vulnerabilities in Sui smart contracts by analyzing compiled bytecode and semantic execution patterns—going far beyond surface-level linting.

SUIZERO is designed for environments where shared objects, capabilities, and economic invariants create attack surfaces that traditional scanners miss. With over **330+ specialized detectors**, it offers comprehensive protection against known and emerging threats in the Sui ecosystem.

---
### 🔬 Advanced Detection Capabilities
SUIZERO doesn't just read code; it simulates execution paths to find:

*   **🕵️ Phantom Authorization**: Parameters that *look* like security checks but are actually ignored.
*   **⏳ Temporal Bugs**: Race conditions between object inspection and mutation.
*   **⚖️ Economic Invariants**: Mathematical asymmetries in deposit/withdraw logic.
*   **🎲 Randomness & Oracle Manipulation**: Predictable randomness sources and single-point-of-failure oracle patterns.
*   **🔄 State Machine Violations**: Invalid state transitions and race condition vulnerabilities.
*   **⬆️ Upgradeability Issues**: Missing initialization guards and unauthorized upgrade access.
*   **💸 MEV & Front-running**: Auction vulnerabilities and slippage manipulation opportunities.




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

### Quick Installation Script (Coming Soon)

For convenience, you can also use our quick installation script:

```bash
# Coming soon - Automated installation
bash <(curl -s https://raw.githubusercontent.com/kaveyjoe/SUIZERO/main/scripts/install.sh)
```

### Docker Installation (Alternative Method)

If you prefer containerized execution:

```bash
# Build the Docker image
docker build -t suizero .

# Run analysis on your project
docker run --rm -v $(pwd)/your_project:/workspace suizero analyze /workspace/build
```

---
## 🚀 Usage Guide

### 1. Build Your Contract
Generate the bytecode artifacts (`.mv` files):
```bash
cd your_project
sui move build
```

### 2. Run Enhanced Security Audit
Scan the artifacts for vulnerabilities with our expanded detection engine:

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

### 3. Advanced Analysis Features

With our enhanced detection capabilities, you can now run more targeted analyses:

```bash
# 🎯 Run specific vulnerability class detectors
./target/release/suizero analyze ./build --detector-class randomness-oracle
./target/release/suizero analyze ./build --detector-class state-machine
./target/release/suizero analyze ./build --detector-class upgradeability
./target/release/suizero analyze ./build --detector-class mev-frontrunning

# 📊 Compare with baseline to track improvements
./target/release/suizero analyze ./build --baseline previous-results.json --diff

# 🔍 Focus on specific severity levels
./target/release/suizero analyze ./build --min-severity high --exit-code 1
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

### 5. Advanced Usage Examples

```bash
# 🚨 Critical Only Mode - Focus on highest priority issues
./target/release/suizero analyze ./build --min-severity critical

# 📊 Comprehensive Scan - All vulnerability types
./target/release/suizero analyze ./build --all-detectors

# 🎯 Targeted Analysis - Specific vulnerability classes
./target/release/suizero analyze ./build --detector-class reentrancy
./target/release/suizero analyze ./build --detector-class arithmetic
./target/release/suizero analyze ./build --detector-class access-control

# 📈 CI/CD Pipeline Integration
./target/release/suizero analyze ./build --format json --exit-code-threshold high

# 📅 Scheduled Monitoring - Track vulnerability evolution
./target/release/suizero analyze ./build --baseline previous_report.json
```



## 🛡️ Vulnerability Types Detected

SUIZERO provides comprehensive coverage across multiple vulnerability classes:

### Core Security Issues
*   **Reentrancy Attacks** - Checks-Effects-Interactions pattern violations
*   **Integer Overflow/Underflow** - Arithmetic vulnerabilities
*   **Access Control Bypass** - Capability theater and privilege escalation
*   **Arithmetic Bugs** - Division by zero, unexpected behaviors

### Advanced Threats
*   **Temporal Vulnerabilities** - TOCTOU (Time-of-check Time-of-use) and race conditions
*   **Oracle & Randomness Manipulation** - Predictable sources and single-point-of-failure
*   **MEV & Front-running** - Arbitrage opportunities and transaction ordering attacks
*   **State Machine Issues** - Invalid state transitions and double-spending

### Upgradeability & Governance
*   **Initialization Vulnerabilities** - Missing constructor guards
*   **Upgrade Access Control** - Unauthorized upgrade paths
*   **Storage Layout Collisions** - Upgrade conflicts

### Financial & DeFi Risks
*   **Economic Invariants** - Deposit/withdraw imbalances
*   **Flash Loan Attacks** - Capital manipulation
*   **Governance Exploits** - Voting manipulation

### Denial of Service
*   **Gas Exhaustion** - Loop and computation vulnerabilities
*   **Storage DOS** - Unbounded growth attacks
*   **Resource Exhaustion** - Service disruption vectors

---

## 📚 Documentation

*   [🏗️ System Architecture](docs/DOCUMENTATION.md) - How it works.
*   [📜 Validation Report](docs/VALIDATION_REPORT.md) - Proof of accuracy.
*   [🧪 Test Examples](examples/) - Try it yourself.
*   [📊 Sample Analysis Report](docs/suizero_analysis_results.md) - Example output from analyzing vulnerable contracts.

---

## 📊 Validation & Accuracy

SUIZERO has been rigorously tested against known vulnerability benchmarks:

*   **Detection Rate**: 85%+ for known vulnerability types
*   **False Positive Rate**: <10% in production environments
*   **Performance**: Sub-50ms analysis per contract module
*   **Coverage**: 330+ vulnerability patterns across 15+ categories

Our validation suite includes intentionally vulnerable "Capture the Flag" style contracts to ensure real-world effectiveness.





## 🚀 Getting Started Checklist

*   [ ] Install Rust toolchain and build tools
*   [ ] Clone the SUIZERO repository
*   [ ] Build the analyzer binary
*   [ ] Run on your first Sui Move project
*   [ ] Integrate into your CI/CD pipeline
*   [ ] Review sample reports in the documentation
*   [ ] Explore advanced detector configurations

## 📞 Support & Community

*   **Bug Reports**: Open an issue in the GitHub repository
*   **Feature Requests**: Submit via GitHub issues with `[FEATURE]` prefix
*   **Security Issues**: Contact directly via private channel
*   **Community**: Join discussions in the Issues section

## 🤝 Acknowledgements

Special thanks to the **Sui Foundation** and **Mysten Labs** for creating Move, a language that makes formal verification possible.

---
<div align="center">
  <sub>Built with ❤️ by KAVEYJOE
</div>
