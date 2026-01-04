# User Guide: Sui Security Analyzer

## Prerequisites

- **Rust**: Version 1.70 or higher (`rustc --version`)
- **Move Tools** (Optional but recommended): `sui` CLI for building source code.

## Getting Started

### 1. Build the Tool
Compile the analyzer for maximum performance:
```bash
cargo build --release
```
The binary will be located at `target/release/sui-analyzer`.

### 2. Prepare Your Target
The analyzer scans **compiled Move bytecode (`.mv` files)**. It does not scan valid source code directly (though it can inspect it for context).

If you have a Move project source:
```bash
# In your Move project root
sui move build
```
This will generate `.mv` files in `build/<ProjectName>/bytecode_modules/`.

### 3. Run Scanning

#### Standard Scan
Scan a directory for all issues Low severity and above:
```bash
./target/release/sui-analyzer analyze ./build/MyProject/bytecode_modules
```

#### High-Value Audit
Scan only for Critical and High severity issues (useful for CI/CD):
```bash
./target/release/sui-analyzer analyze ./build --severity high
```

#### JSON Output
Generate a machine-readable report:
```bash
./target/release/sui-analyzer analyze ./build --format json --output report.json
```

## Workflows

### GitHub Actions Integration
You can integrate this tool into your CI pipeline.

```yaml
steps:
  - uses: actions/checkout@v3
  - name: Build Move
    run: sui move build
  - name: Run Security Scan
    run: |
      cargo run --release -- analyze ./build --fail-on-critical
```

### Analyzing External Repositories (Manual)
1. `git clone <repo_url>`
2. `sui move build`
3. `sui-analyzer analyze ./build`

## Troubleshooting

- **"No issues found"**: Ensure you are pointing the tool at a directory containing `.mv` files, not just `.move` source files.
- **"Command not found"**: Ensure `target/release` is in your PATH or use `cargo run`.

## Reporting False Positives
If you encounter a false positive, please open an issue with the module bytecode or source snippet.
