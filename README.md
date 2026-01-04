# SUIZERO

**The Enterprise-Grade SUI Security Analyzer**

SUIZERO is a high-performance static analysis engine for validating Sui Move smart contracts. It detects critical security vulnerabilities, logic flaws, and economic risks directly from compiled bytecode with **100% validated accuracy** on known benchmarks.

## 🛡️ Key Features

- **Deep Bytecode Analysis**: Operates on `.mv` files for true-to-chain verification.
- **Phantom Auth Detection**: The only tool that catches "Fake Security" patterns (SUI-033).
- **Temporal Logic**: Detects TOCTOU and Race Conditions (SUI-036).
- **Logic Assurance**: Validates Cross-Function Invariants (SUI-034).
- **Precision**: Zero False Positives in production mode.

## 📦 Installation

```bash
git clone https://github.com/suizero/suizero
cd sui-security-analyzer
cargo build --release --bin suizero
```

## 🚀 How to Run (2 Steps)

### Step 1: Build Your Contract
Generate the bytecode artifacts:
```bash
cd your_project
sui move build
```

### Step 2: Run SUIZERO
Scan the build artifacts:
```bash
# Basic Audit
./target/release/suizero analyze ./build

# Detailed Markdown Report
./target/release/suizero analyze ./build --format markdown > audit_report.md

# CI/CD Mode (JSON Output)
./target/release/suizero analyze ./build --format json
```

---

## 📚 Documentation & Resources

- [Validation Report](docs/VALIDATION_REPORT.md): Proof of 100% detection accuracy.
- [Status & Roadmap](docs/STATUS.md): Current development status.
- [Deployment Guide](docs/UPLOAD_INSTRUCTIONS.md): How to deploy/upload this tool.
- [Examples](examples/): Vulnerable contracts for testing.

## 🧪 Testing

We provide a suite of vulnerable contracts in `examples/vulnerable_project` to verify the analyzer.

```bash
# Build the examples
cd examples/vulnerable_project
sui move build

# Run the analyzer on examples
cd ../..
./target/release/suizero analyze examples/vulnerable_project/build
```




## Acknowledgements

Special thanks to the **Sui Foundation** and the **Mysten Labs** team for designing **Sui Move**, a language that prioritizes safety and verification.

## License
MIT
