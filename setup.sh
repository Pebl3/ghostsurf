#!/bin/bash
# IIS Kernel Auth Relay - Setup Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "=== IIS Kernel Auth Relay Setup ==="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[*] Found Python $PYTHON_VERSION"

# Create virtual environment
if [ -d "$VENV_DIR" ]; then
    echo "[*] Virtual environment already exists, removing..."
    rm -rf "$VENV_DIR"
fi

echo "[*] Creating virtual environment..."
python3 -m venv "$VENV_DIR"

# Activate and install
echo "[*] Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip > /dev/null
pip install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Usage:"
echo "  ./run.sh -t https://target-iis-server/ -socks --kernel-auth"
echo ""
echo "Or activate the virtual environment manually:"
echo "  source venv/bin/activate"
echo "  python iis-relay.py -h"
