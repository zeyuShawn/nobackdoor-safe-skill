# Security Auditor Skill 🛡️

A local Agent Skill designed to audit other Agent Skills for supply chain poisoning attacks.

## Features
- **Static Analysis**: Scans directories for suspicious patterns.
- **Threat Detection**:
    - `curl | bash` / `wget | sh` piping.
    - Base64 obfuscated payloads.
    - macOS Quarantine removal (`xattr -c`).
    - Hidden executables (Mach-O, ELF, PE).
    - Raw IP address connections.
- **Whitelisting**: Supports a JSON-based whitelist to ignore known safe files.

## Usage
This skill is designed to be used with an Agent (like OpenClaw or local LLM agents).

1.  **Install**: Clone this repository into your skill directory.
2.  **Trigger**: Tell your agent "Scan this directory for security issues".
3.  **Report**: The agent will run the scanner and present a report.

## Directory Structure
- `SKILL.md`: The main instruction file for the Agent.
- `scripts/`: Contains the logical scanner script (`security_scanner.py`).
- `data/`: Contains the `whitelist.json`.
- `tests/`: Contains mock malicious files for verification.

## Disclaimer
This tool is for educational and defensive purposes only. The `tests/` directory contains simulated malicious scripts to verify the scanner's functionality. DO NOT EXECUTE files in `tests/mock_malicious/`.
