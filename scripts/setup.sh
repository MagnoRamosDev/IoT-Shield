#!/bin/bash
set -e

echo "[+] Setting up AI Pipeline environment..."

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed."
    exit 1
fi

echo "[+] Creating virtual environment..."
python3 -m venv venv

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Installing requirements..."
pip install --upgrade pip
pip install -r config/requirements.txt

echo "[+] Creating required directories..."
mkdir -p data/tmp results

echo "[+] Setup complete! Use 'bash scripts/run.sh' to execute the pipeline."
