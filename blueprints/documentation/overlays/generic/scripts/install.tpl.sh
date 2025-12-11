#!/bin/bash
# Template System Dependency Installer
# Installs Python dependencies for the 10/10 template system

set -e

echo "🚀 Installing Template System Dependencies..."
echo "=========================================="

# Check if Python is available
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Error: Python is not installed or not in PATH"
    echo "Please install Python 3.9+ and try again"
    exit 1
fi

# Use python if available, otherwise python3
PYTHON_CMD="python"
if ! command -v python &> /dev/null; then
    PYTHON_CMD="python3"
fi

echo "✅ Using Python: $($PYTHON_CMD --version)"

# Check if pip is available
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo "❌ Error: pip is not installed or not in PATH"
    echo "Please install pip and try again"
    exit 1
fi

# Use pip if available, otherwise pip3
PIP_CMD="pip"
if ! command -v pip &> /dev/null; then
    PIP_CMD="pip3"
fi

echo "✅ Using pip: $($PIP_CMD --version)"

# Install dependencies
echo ""
echo "📦 Installing dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    $PIP_CMD install -r requirements.txt
    echo "✅ Dependencies installed successfully"
else
    echo "⚠️  Warning: requirements.txt not found"
    echo "Installing minimal dependencies..."
    $PIP_CMD install pyyaml>=6.0 pathlib2>=2.3.0
    echo "✅ Minimal dependencies installed"
fi

# Verify installation
echo ""
echo "🔍 Verifying installation..."
$PYTHON_CMD -c "import yaml; print('✅ PyYAML installed successfully')" || {
    echo "❌ Error: PyYAML installation failed"
    exit 1
}

# Test core scripts
echo ""
echo "🧪 Testing core scripts..."
echo "Testing tier_config.py..."
$PYTHON_CMD scripts/tier_config.py --help > /dev/null 2>&1 && echo "✅ tier_config.py working" || echo "❌ tier_config.py failed"

echo "Testing validate_docs.py..."
$PYTHON_CMD scripts/validate_docs.py --help > /dev/null 2>&1 && echo "✅ validate_docs.py working" || echo "❌ validate_docs.py failed"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Run validation: python scripts/validate_docs.py --consistency-report"
echo "  2. Test dynamic config: python scripts/tier_config.py core bash"
echo "  3. Try self-healing: python scripts/self_heal.py --dry-run"
echo ""
echo "📚 For more information, see README.md"
