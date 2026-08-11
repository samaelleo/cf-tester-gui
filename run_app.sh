#!/usr/bin/env bash
# ==============================================================================
# Cloudflare Clean IP Scanner - Linux & macOS Launcher
# ==============================================================================

# Change directory to script root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Detect Python binary
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "❌ Error: Python 3 was not found. Please install Python 3.9+."
    exit 1
fi

# Activate virtualenv if present
if [ -d ".venv" ] && [ -f ".venv/bin/activate" ]; then
    source ".venv/bin/activate"
    PY_CMD="python"
elif [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    source "venv/bin/activate"
    PY_CMD="python"
fi

echo "========================================================"
echo "  🚀 Starting Cloudflare Clean IP Scanner..."
echo "  💻 System: $(uname -s) ($(uname -m))"
echo "  🐍 Python: $($PY_CMD --version)"
echo "========================================================"

# Run main launcher with passed arguments
$PY_CMD main.py "$@"
