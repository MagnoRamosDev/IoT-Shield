#!/bin/bash
set -e

# Activate python virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Virtual environment not found. Please run 'bash scripts/setup.sh' first."
    exit 1
fi

export PYTHONPATH="$PWD"

if [ "$#" -eq 0 ]; then
    python src/pipeline.py --help
else
    python src/pipeline.py "$@"
fi
