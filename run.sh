#!/bin/bash
# IIS Kernel Auth Relay - Run Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Error: Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

source "$VENV_DIR/bin/activate"
python "$SCRIPT_DIR/iis-relay.py" "$@"
