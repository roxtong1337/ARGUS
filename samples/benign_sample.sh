#!/bin/bash
# Synthetic benign sample for REA tests: should score clean.
set -euo pipefail

VERSION="1.4.2"
LOG_DIR="/var/log/myapp"

mkdir -p "$LOG_DIR"
echo "starting myapp $VERSION" >> "$LOG_DIR/myapp.log"

for file in /var/log/myapp/*.log; do
    gzip -k "$file"
done

echo "backup complete, ${VERSION} finished"
