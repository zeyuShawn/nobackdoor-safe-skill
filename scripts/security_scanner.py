import os
import sys
import argparse
import json
import re
import mimetypes
import hashlib
import ast

# --- Configuration ---

IOC_PATTERNS = [
    {
        "id": "CMD_CURL_BASH",
        "level": "CRITICAL",
        "regex": r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|perl|ruby)",
        "desc": "Detects 'curl | bash' style piping, highly suspicious for installers."
    },
    {
        "id": "CMD_XATTR_QUARANTINE",
        "level": "CRITICAL",
        "regex": r"xattr\s+-[a-zA-Z]*c[a-zA-Z]*\s+",
        "desc": "Detects removal of macOS Quarantine attribute (xattr -c), often used by malware."
    },
    {
        "id": "CMD_BASE64_DECODE",
        "level": "HIGH",
        "regex": r"base64\s+(-d|--decode)",
        "desc": "Detects base64 decoding, often used to obfuscate payloads."
    },
    {
        "id": "NET_raw_IP",
        "level": "HIGH",
        "regex": r"http(s)?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        "desc": "Detects URL using raw IP address instead of domain name."
    },
    {
        "id": "CODE_EVAL",
        "level": "HIGH",
        "regex": r"\beval\(",
        "desc": "Detects use of 'eval()', often used for dynamic code execution."
    },
     {
        "id": "CODE_SUSPICIOUS_IMPORTS",
        "level": "WARNING",
        "regex": r"import\s+(socket|subprocess|pty|platform)|from\s+(socket|subprocess|pty|platform)\s+import",
        "desc": "Detects imports often used in reverse shells (socket, subprocess, pty)."
    }
]

BINARY_MAGIC_NUMBERS = {
    # Mach-O (macOS)
    b'\xfe\xed\xfa\xcf': "Mach-O 64-bit (macOS)",
    b'\xcf\xfa\xed\xfe': "Mach-O 64-bit (macOS)",
    b'\xfe\xed\xfa\xce': "Mach-O 32-bit (macOS)",
    b'\xce\xfa\xed\xfe': "Mach-O 32-bit (macOS)",
    b'\xca\xfe\xba\xbe': "Mach-O Universal (macOS)",
    # ELF (Linux)
    b'\x7fELF': "ELF Binary (Linux)",
    # PE (Windows)
    b'MZ': "PE Binary (Windows)"
}

# --- Whitelist Logic ---

def load_whitelist(path):
    if not path or not os.path.exists(path):
        return {"hashes": [], "paths": [], "patterns": []}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error loading whitelist: {e}\n")
        return {"hashes": [], "paths": [], "patterns": []}

def is_whitelisted(file_path, file_hash, whitelist):
    # 1. Check Path (Relative matching could be implemented, here using exact basename or full path for simplicity)
    # Ideally, paths in whitelist should be relative to the scan root.
    # For now, we check if the filename matches any 'safe' filenames (risky but simple) or exact path matches.
    if file_path in whitelist.get('paths', []):
        return True
    
    # 2. Check Hash
    if file_hash in whitelist.get('hashes', []):
        return True
    
    return False

# --- Scanning Logic ---

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def check_binary(file_path):
    """Checks if a file is a suspicious hidden binary."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
        
        for magic, desc in BINARY_MAGIC_NUMBERS.items():
            if header.startswith(magic):
                # It's a binary. Is it suspicious?
                # If it has no extension or a misleading one (like .txt, .md, .sh), it's suspicious.
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ['.md', '.txt', '.json', '.sh', '.py', '.js', '']:
                    return f"Hidden Binary File ({desc}) masked as '{ext}'"
                
                # Even if it has a binary extension, in a 'skill' script folder, binaries are suspicious.
                return f"Executable Binary Found ({desc})"
    except:
        pass
    return None

def scan_text_file(file_path):
    issues = []
    try:
        # Read file. Handle encoding errors loosely.
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()

        for pattern in IOC_PATTERNS:
            matches = re.findall(pattern['regex'], content, re.MULTILINE | re.IGNORECASE)
            if matches:
                 # Find line numbers for the first few matches
                detected_lines = []
                for i, line in enumerate(lines):
                    if re.search(pattern['regex'], line, re.IGNORECASE):
                        detected_lines.append(i + 1)
                        if len(detected_lines) >= 3: break
                
                issues.append({
                    "id": pattern['id'],
                    "level": pattern['level'],
                    "description": pattern['desc'],
                    "lines": detected_lines,
                    "sample": matches[0] if matches else "N/A"
                })
    except Exception as e:
        pass # Binary or unreadable
    return issues

def scan_directory(target_path, whitelist_path):
    results = []
    whitelist = load_whitelist(whitelist_path)
    
    abs_target = os.path.abspath(target_path)
    
    for root, dirs, files in os.walk(abs_target):
        # Check for hidden directories
        for d in dirs:
            if d.startswith('.') and d != '.git':
                 results.append({
                    "file": os.path.join(root, d),
                    "type": "directory",
                    "level": "WARNING",
                    "issues": [{"id": "HIDDEN_DIR", "level": "WARNING", "description": "Hidden directory found"}]
                })

        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, abs_target)
            
            # 1. basic properties
            file_hash = calculate_sha256(file_path)
            
            # 2. Whitelist Check
            if is_whitelisted(rel_path, file_hash, whitelist):
                continue

            file_issues = []

            # 3. Binary Check
            binary_warning = check_binary(file_path)
            if binary_warning:
                file_issues.append({
                    "id": "SUSPICIOUS_BINARY",
                    "level": "CRITICAL",  # Binaries in skills are generally very bad
                    "description": binary_warning
                })
            
            # 4. Text Check (if not binary or if valid extension)
            # We scan everything that isn't clearly a binary blob, just in case.
            text_issues = scan_text_file(file_path)
            file_issues.extend(text_issues)

            if file_issues:
                # Calculate max severity
                levels = [x['level'] for x in file_issues]
                severity = "WARNING"
                if "CRITICAL" in levels: severity = "CRITICAL"
                elif "HIGH" in levels: severity = "HIGH"

                results.append({
                    "file": rel_path,
                    "hash": file_hash,
                    "severity": severity,
                    "issues": file_issues
                })

    return results

# --- Main ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Scanner for Agent Skills")
    parser.add_argument("--target", required=True, help="Target directory to scan")
    parser.add_argument("--whitelist", required=False, help="Path to whitelist JSON")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.target):
        print(json.dumps({"error": f"Target path {args.target} does not exist"}))
        sys.exit(1)

    scan_results = scan_directory(args.target, args.whitelist)
    print(json.dumps(scan_results, indent=2))
