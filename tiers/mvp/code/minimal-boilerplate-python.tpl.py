"""
File: minimal-boilerplate-python.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# Minimal Boilerplate Template (MVP Tier - Python)

## Purpose
Provides the absolute minimum Python code structure for MVP projects following the minimal viable product approach.

## Usage
This template should be used for:
- Prototype applications
- Proof of concepts
- Early-stage startup services
- Internal tools with limited scope

## Structure
```python
#!/usr/bin/env python3
"""
[[.ProjectName]] - Minimal MVP Application
Basic structure for rapid prototyping and validation
Author: [[.Author]]
Version: [[.Version]]
"""

import sys
import logging
from typing import Optional

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MVPApplication:
    """Minimal application class for MVP development"""
    
    def __init__(self):
        self.status = "MVP Application Starting..."
        self.running = False
    
    def initialize_core(self) -> bool:
        """
        Initialize core functionality only
        No advanced configuration, no optional features
        """
        try:
            # Only essential initialization
            logger.info("Initializing core functionality")
            self.status = "MVP Service Running"
            return True
        except Exception as e:
            logger.error(f"Failed to initialize: {e}")
            return False
    
    def start_minimal_service(self):
        """Start minimal service with basic functionality"""
        try:
            self.running = True
            logger.info("MVP Service Running")
            
            # Basic service loop
            while self.running:
                self.perform_basic_action()
                
        except KeyboardInterrupt:
            logger.info("Service stopped by user")
        except Exception as e:
            logger.error(f"Service error: {e}")
        finally:
            self.running = False
    
    def perform_basic_action(self):
        """Basic service functionality"""
        # Add your core business logic here
        logger.info("Performing basic MVP action")
        
        # For demonstration, we'll just sleep
        import time
        time.sleep(1)

def main():
    """Main entry point for MVP application"""
    try:
        # Initialize application
        app = MVPApplication()
        
        # Start core functionality
        if not app.initialize_core():
            logger.error("Failed to initialize application")
            sys.exit(1)
        
        # Start minimal service
        app.start_minimal_service()
        
    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## MVP Guidelines
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: Standard library only when possible
- **Error Handling**: Basic logging and exception handling
- **Testing**: Manual testing sufficient
- **Documentation**: Inline docstrings only

## What's NOT Included (Compared to Core/Full)
- No advanced configuration management
- No comprehensive logging frameworks
- No monitoring/metrics collection
- No automated testing framework
- No API documentation generation
- No deployment automation
- No database integration
- No async/await patterns
- No dependency injection
