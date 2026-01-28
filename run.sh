#!/bin/bash

# Ensure we are in the script's directory
cd "$(dirname "$0")"

# Name of the virtual environment directory
VENV_DIR="venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install dependencies if requirements.txt has changed or first run
# (Simple check: just run pip install, it's fast if already satisfied)
if [ -f "requirements.txt" ]; then
    pip install -q -r requirements.txt
fi

# Run the scanner, passing all arguments from this script to the python script
python3 cf-auth-scanner.py "$@"
