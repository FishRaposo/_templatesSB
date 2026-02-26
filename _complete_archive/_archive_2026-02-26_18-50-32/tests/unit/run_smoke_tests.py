#!/usr/bin/env python3
"""
Quick smoke test runner
Runs basic validation tests to ensure system health
"""

import subprocess
import sys
from pathlib import Path

def run_smoke_tests():
    """Run smoke tests and return result"""
    smoke_test_path = Path(__file__).parent / "test_smoke.py"
    
    if not smoke_test_path.exists():
        print("❌ Smoke test file not found")
        return False
    
    try:
        result = subprocess.run([
            sys.executable, str(smoke_test_path)
        ], capture_output=True, text=True, cwd=smoke_test_path.parent)
        
        print("🧪 Smoke Test Results:")
        print("=" * 40)
        print(result.stdout)
        
        if result.stderr:
            print("Warnings/Errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ All smoke tests passed!")
            return True
        else:
            print(f"❌ Smoke tests failed with exit code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"❌ Error running smoke tests: {e}")
        return False

def main():
    """Main entry point"""
    print("🚀 Running Template System Smoke Tests")
    print("=" * 50)
    
    success = run_smoke_tests()
    
    if success:
        print("🎉 System is healthy!")
        sys.exit(0)
    else:
        print("💥 System health check failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
