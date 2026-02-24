#!/usr/bin/env python3
"""
Tier Detection Script
Purpose: Automatically detect the optimal tier (MVP/Core/Enterprise) based on project requirements
Usage: python scripts/detect-tier.py [--verbose] [--interactive]
"""

import sys
import json
import argparse
from typing import Dict, Tuple, Optional

class TierDetector:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.scores = {"mvp": 0, "core": 0, "enterprise": 0}
        
    def log(self, message: str):
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def ask_question(self, question: str, options: Dict[str, str]) -> str:
        """Ask a question and return the selected option key"""
        print(f"\n{question}")
        for i, (key, desc) in enumerate(options.items(), 1):
            print(f"{i}. {desc}")
        
        while True:
            try:
                choice = input("Enter your choice (number): ").strip()
                option_keys = list(options.keys())
                if choice.isdigit() and 1 <= int(choice) <= len(option_keys):
                    return option_keys[int(choice) - 1]
                else:
                    print("Invalid choice. Please enter a number.")
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(1)
    
    def calculate_project_type_score(self, project_type: str):
        """Calculate tier scores based on project type"""
        if project_type == "mobile":
            self.scores["core"] += 2  # Mobile apps usually need production features
            self.scores["enterprise"] += 1
        elif project_type == "web":
            self.scores["core"] += 2  # Web apps benefit from production setup
            self.scores["mvp"] += 1
        elif project_type == "backend":
            self.scores["core"] += 2  # Backend services need production features
            self.scores["enterprise"] += 1
        elif project_type == "not_sure":
            self.scores["core"] += 3  # Default to core for balanced approach
        
        self.log(f"Project type scores: {self.scores}")
    
    def calculate_team_timeline_score(self, team_timeline: str):
        """Calculate tier scores based on team size and timeline"""
        if team_timeline == "small_team":
            self.scores["mvp"] += 3
            self.scores["core"] += 1
        elif team_timeline == "medium_team":
            self.scores["core"] += 3
            self.scores["mvp"] += 1
        elif team_timeline == "large_team":
            self.scores["enterprise"] += 3
            self.scores["core"] += 2
        
        self.log(f"Team/timeline scores: {self.scores}")
    
    def calculate_compliance_score(self, compliance: str):
        """Calculate tier scores based on compliance requirements"""
        if compliance == "none":
            self.scores["mvp"] += 2
            self.scores["core"] += 1
        elif compliance == "future_possible":
            self.scores["core"] += 3
            self.scores["enterprise"] += 1
        elif compliance == "required":
            self.scores["enterprise"] += 3
            self.scores["core"] += 1
        
        self.log(f"Compliance scores: {self.scores}")
    
    def calculate_security_score(self, security: str):
        """Calculate tier scores based on security needs"""
        if security == "basic":
            self.scores["mvp"] += 2
            self.scores["core"] += 1
        elif security == "advanced":
            self.scores["enterprise"] += 3
            self.scores["core"] += 2
        elif security == "enterprise":
            self.scores["enterprise"] += 3
            self.scores["core"] += 1
        
        self.log(f"Security scores: {self.scores}")
    
    def detect_interactive(self) -> Tuple[str, Dict]:
        """Run interactive tier detection"""
        print("🎯 Universal Tier Detection Wizard")
        print("=" * 40)
        print("Answer a few questions to find your optimal tier...")
        
        # Question 1: Project Type
        project_options = {
            "mobile": "Mobile App (Flutter/React Native)",
            "web": "Web Application (React/Node.js)",
            "backend": "Backend Service (Python/Go)",
            "not_sure": "Not sure / Other"
        }
        project_type = self.ask_question("What type of project are you building?", project_options)
        self.calculate_project_type_score(project_type)
        
        # Question 2: Team Size & Timeline
        team_options = {
            "small_team": "1-2 people, < 1 month",
            "medium_team": "3-10 people, 1-6 months", 
            "large_team": "10+ people, 6+ months"
        }
        team_timeline = self.ask_question("What's your team size and timeline?", team_options)
        self.calculate_team_timeline_score(team_timeline)
        
        # Question 3: Compliance Requirements
        compliance_options = {
            "none": "No compliance requirements",
            "future_possible": "Compliance might be needed in future",
            "required": "GDPR/HIPAA/SOC 2 or similar required"
        }
        compliance = self.ask_question("What are your compliance requirements?", compliance_options)
        self.calculate_compliance_score(compliance)
        
        # Question 4: Security Needs
        security_options = {
            "basic": "Basic authentication is enough",
            "advanced": "Advanced security needed (MFA, encryption)",
            "enterprise": "Enterprise-grade security required"
        }
        security = self.ask_question("What are your security needs?", security_options)
        self.calculate_security_score(security)
        
        # Determine recommended tier
        recommended_tier = max(self.scores, key=self.scores.get)
        
        return recommended_tier, {
            "project_type": project_type,
            "team_timeline": team_timeline,
            "compliance": compliance,
            "security": security,
            "scores": self.scores.copy()
        }
    
    def detect_from_config(self, config_file: str) -> Tuple[str, Dict]:
        """Detect tier from configuration file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            self.log(f"Loaded config: {config}")
            
            # Calculate scores from config
            project_type = config.get("project_type", "not_sure")
            self.calculate_project_type_score(project_type)
            
            team_timeline = config.get("team_timeline", "medium_team")
            self.calculate_team_timeline_score(team_timeline)
            
            compliance = config.get("compliance", "none")
            self.calculate_compliance_score(compliance)
            
            security = config.get("security", "basic")
            self.calculate_security_score(security)
            
            recommended_tier = max(self.scores, key=self.scores.get)
            
            return recommended_tier, {
                "config_file": config_file,
                "scores": self.scores.copy()
            }
            
        except Exception as e:
            print(f"Error reading config file: {e}")
            return "core", {"error": str(e)}
    
    def print_recommendation(self, tier: str, details: Dict):
        """Print the tier recommendation with explanation"""
        tier_descriptions = {
            "mvp": {
                "name": "MVP Tier (Version 1.0)",
                "time": "15-30 minutes",
                "files": "4-7 files",
                "use_case": "Quick prototypes and minimum viable products"
            },
            "core": {
                "name": "Core Tier (Version 2.0)",
                "time": "2-4 hours", 
                "files": "15-25 files",
                "use_case": "Production applications with comprehensive features"
            },
            "enterprise": {
                "name": "Enterprise Tier (Version 3.0)",
                "time": "1-2 days",
                "files": "30-50 files", 
                "use_case": "Enterprise systems with security and compliance"
            }
        }
        
        desc = tier_descriptions[tier]
        
        print("\n" + "=" * 50)
        print(f"🎯 RECOMMENDED TIER: {desc['name']}")
        print("=" * 50)
        print(f"⏱️  Setup Time: {desc['time']}")
        print(f"📁 Files Generated: {desc['files']}")
        print(f"🎯 Best For: {desc['use_case']}")
        
        if self.verbose and "scores" in details:
            print(f"\n📊 Score Breakdown:")
            for t, score in details["scores"].items():
                print(f"   {t.upper()}: {score} points")
        
        print(f"\n🚀 Next Steps:")
        print(f"   Run: python scripts/auto-setup.py --tier {tier}")
        print(f"   Or: See QUICKSTART.md for manual setup instructions")

def main():
    parser = argparse.ArgumentParser(description="Detect optimal project tier")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--interactive", "-i", action="store_true", default=True, help="Interactive mode (default)")
    parser.add_argument("--config", "-c", help="Detect from configuration file")
    parser.add_argument("--output", "-o", help="Output results to JSON file")
    
    args = parser.parse_args()
    
    detector = TierDetector(verbose=args.verbose)
    
    if args.config:
        tier, details = detector.detect_from_config(args.config)
    else:
        tier, details = detector.detect_interactive()
    
    detector.print_recommendation(tier, details)
    
    # Save results if requested
    if args.output:
        result = {
            "recommended_tier": tier,
            "details": details,
            "timestamp": str(datetime.datetime.now())
        }
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n📄 Results saved to: {args.output}")

if __name__ == "__main__":
    import datetime
    main()
