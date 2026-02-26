#!/usr/bin/env python3
"""
Intelligent Stack Detection Script
Purpose: Analyze project requirements and recommend optimal technology stack
Usage: python scripts/detect-stack.py [--verbose] [--description "project description"]
"""

import sys
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class StackRecommendation:
    stack: str
    score: float
    reasoning: List[str]
    confidence: str
    use_cases: List[str]

class StackDetector:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.templates_root = Path(__file__).parent.parent
        
        # Stack characteristics and keywords
        self.stack_profiles = {
            "flutter": {
                "keywords": ["mobile", "ios", "android", "flutter", "dart", "cross-platform", "ui", "native"],
                "file_patterns": ["*.dart", "pubspec.yaml", "lib/main.dart"],
                "use_cases": ["Mobile Apps", "Cross-platform Development", "Native Performance"],
                "strengths": ["Single codebase for iOS/Android", "Native performance", "Rich UI components"],
                "team_skills": ["dart", "mobile", "ui"],
                "performance": "high",
                "learning_curve": "medium"
            },
            "react_native": {
                "keywords": ["mobile", "react native", "cross-platform", "javascript", "react", "mobile app"],
                "file_patterns": ["*.jsx", "App.js", "package.json", "react-native"],
                "use_cases": ["Cross-platform Mobile", "Web Code Reuse", "Fast Development"],
                "strengths": ["React ecosystem", "Hot reload", "Code sharing with web"],
                "team_skills": ["javascript", "react", "web"],
                "performance": "medium",
                "learning_curve": "low"
            },
            "react": {
                "keywords": ["web", "frontend", "react", "javascript", "spa", "single page", "ui", "component"],
                "file_patterns": ["*.jsx", "App.jsx", "package.json", "src/", "components/"],
                "use_cases": ["Web Applications", "Single-page Apps", "Component-based UI"],
                "strengths": ["Large ecosystem", "Component architecture", "Strong community"],
                "team_skills": ["javascript", "react", "web"],
                "performance": "medium",
                "learning_curve": "low"
            },
            "node": {
                "keywords": ["backend", "api", "server", "node", "javascript", "rest", "microservice"],
                "file_patterns": ["*.js", "app.js", "server.js", "package.json", "routes/"],
                "use_cases": ["Backend APIs", "Microservices", "REST Services"],
                "strengths": ["Fast development", "Large ecosystem", "JavaScript everywhere"],
                "team_skills": ["javascript", "backend", "api"],
                "performance": "medium",
                "learning_curve": "low"
            },
            "python": {
                "keywords": ["python", "data", "machine learning", "ml", "ai", "backend", "api", "science"],
                "file_patterns": ["*.py", "main.py", "requirements.txt", "app.py", "pipfile"],
                "use_cases": ["Data Science", "ML Applications", "Backend Services"],
                "strengths": ["Rich ecosystem", "Rapid prototyping", "Scientific libraries"],
                "team_skills": ["python", "data", "science"],
                "performance": "medium",
                "learning_curve": "low"
            },
            "go": {
                "keywords": ["go", "golang", "performance", "microservice", "cli", "systems", "concurrent"],
                "file_patterns": ["*.go", "main.go", "go.mod", "go.sum"],
                "use_cases": ["High-performance Services", "Microservices", "CLI Tools"],
                "strengths": ["Performance", "Concurrency", "Single binary deployment"],
                "team_skills": ["go", "systems", "performance"],
                "performance": "high",
                "learning_curve": "medium"
            }
        }
        
        # Platform-specific keywords
        self.platform_keywords = {
            "mobile": ["mobile", "ios", "android", "app", "phone", "tablet"],
            "web": ["web", "browser", "frontend", "spa", "website"],
            "backend": ["backend", "api", "server", "service", "microservice"],
            "data": ["data", "analytics", "ml", "ai", "machine learning", "science"],
            "performance": ["performance", "speed", "scalability", "concurrent", "high-throughput"]
        }

    def log(self, message: str):
        """Print verbose messages if enabled"""
        if self.verbose:
            print(f"🔍 {message}")

    def analyze_description(self, description: str) -> Dict[str, float]:
        """Analyze project description for stack compatibility"""
        scores = {}
        desc_lower = description.lower()
        
        for stack, profile in self.stack_profiles.items():
            score = 0.0
            
            # Keyword matching
            keyword_matches = sum(1 for keyword in profile["keywords"] 
                                if keyword in desc_lower)
            score += keyword_matches * 10
            
            # Platform matching
            for platform, keywords in self.platform_keywords.items():
                if any(keyword in desc_lower for keyword in keywords):
                    if platform == "mobile" and stack in ["flutter", "react_native"]:
                        score += 15
                    elif platform == "web" and stack == "react":
                        score += 15
                    elif platform == "backend" and stack in ["node", "python", "go"]:
                        score += 15
                    elif platform == "data" and stack == "python":
                        score += 15
                    elif platform == "performance" and stack == "go":
                        score += 15
            
            scores[stack] = score
            
        return scores

    def analyze_existing_files(self, directory: Path) -> Dict[str, float]:
        """Analyze existing files in directory for stack clues"""
        scores = {}
        
        if not directory.exists():
            return scores
            
        for stack, profile in self.stack_profiles.items():
            score = 0.0
            
            # Check for file patterns
            for pattern in profile["file_patterns"]:
                if "*" in pattern:
                    matches = list(directory.rglob(pattern))
                    score += len(matches) * 5
                else:
                    if (directory / pattern).exists():
                        score += 10
            
            scores[stack] = score
            
        return scores

    def ask_platform_questions(self) -> Dict[str, float]:
        """Ask interactive questions about platform requirements"""
        scores = {stack: 0.0 for stack in self.stack_profiles.keys()}
        
        print("\n🎯 Platform Requirements")
        print("-" * 30)
        
        # Primary platform
        platforms = ["Mobile (iOS/Android)", "Web Application", "Backend API", "Data Science/ML", "CLI/Systems"]
        platform_weights = {
            "Mobile (iOS/Android)": {"flutter": 20, "react_native": 20},
            "Web Application": {"react": 20},
            "Backend API": {"node": 15, "python": 10, "go": 15},
            "Data Science/ML": {"python": 20},
            "CLI/Systems": {"go": 20}
        }
        
        print("What is your primary target platform?")
        for i, platform in enumerate(platforms, 1):
            print(f"{i}. {platform}")
        
        choice = input("Enter choice (1-5): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= 5:
            platform = platforms[int(choice) - 1]
            for stack, weight in platform_weights.get(platform, {}).items():
                scores[stack] += weight
        
        # Team skills
        print("\nWhat are your team's primary skills?")
        skills = ["JavaScript/React", "Python/Data Science", "Systems Programming", "Mobile Development"]
        skill_weights = {
            "JavaScript/React": {"react": 15, "react_native": 10, "node": 10},
            "Python/Data Science": {"python": 20},
            "Systems Programming": {"go": 20},
            "Mobile Development": {"flutter": 15, "react_native": 15}
        }
        
        for i, skill in enumerate(skills, 1):
            print(f"{i}. {skill}")
        
        choice = input("Enter choice (1-4): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= 4:
            skill = skills[int(choice) - 1]
            for stack, weight in skill_weights.get(skill, {}).items():
                scores[stack] += weight
        
        # Performance requirements
        print("\nWhat are your performance requirements?")
        perf_options = ["Standard (rapid development)", "High (concurrent users)", "Maximum (low latency)"]
        perf_weights = {
            "Standard (rapid development)": {"node": 10, "python": 10, "react": 10, "react_native": 10},
            "High (concurrent users)": {"go": 15, "node": 10},
            "Maximum (low latency)": {"go": 20, "flutter": 10}
        }
        
        for i, perf in enumerate(perf_options, 1):
            print(f"{i}. {perf}")
        
        choice = input("Enter choice (1-3): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= 3:
            perf = perf_options[int(choice) - 1]
            for stack, weight in perf_weights.get(perf, {}).items():
                scores[stack] += weight
        
        return scores

    def generate_recommendations(self, description_scores: Dict[str, float], 
                                file_scores: Dict[str, float], 
                                question_scores: Dict[str, float]) -> List[StackRecommendation]:
        """Generate final stack recommendations with reasoning"""
        
        # Combine all scores
        final_scores = {}
        for stack in self.stack_profiles.keys():
            final_scores[stack] = (
                description_scores.get(stack, 0) * 1.0 +
                file_scores.get(stack, 0) * 2.0 +
                question_scores.get(stack, 0) * 1.5
            )
        
        # Sort by score
        sorted_stacks = sorted(final_scores.items(), key=lambda x: x[1], reverse=True)
        
        recommendations = []
        for stack, score in sorted_stacks[:3]:  # Top 3 recommendations
            profile = self.stack_profiles[stack]
            
            # Generate reasoning
            reasoning = []
            if description_scores.get(stack, 0) > 0:
                reasoning.append("Matches project description keywords")
            if file_scores.get(stack, 0) > 0:
                reasoning.append("Compatible with existing files")
            if question_scores.get(stack, 0) > 0:
                reasoning.append("Fits platform and team requirements")
            
            # Determine confidence
            if score >= 40:
                confidence = "High"
            elif score >= 20:
                confidence = "Medium"
            else:
                confidence = "Low"
            
            recommendations.append(StackRecommendation(
                stack=stack,
                score=score,
                reasoning=reasoning or ["Basic compatibility"],
                confidence=confidence,
                use_cases=profile["use_cases"]
            ))
        
        return recommendations

    def detect_interactive(self, description: str = None) -> Tuple[str, List[StackRecommendation]]:
        """Run interactive stack detection"""
        print("🧠 Intelligent Stack Detection")
        print("=" * 40)
        print("Analyzing your project to recommend the best technology stack...")
        print()
        
        # Get project description if not provided
        if not description:
            description = input("Describe your project in a few sentences: ").strip()
        
        self.log(f"Analyzing description: {description}")
        description_scores = self.analyze_description(description)
        
        # Analyze existing files
        current_dir = Path.cwd()
        self.log(f"Analyzing files in: {current_dir}")
        file_scores = self.analyze_existing_files(current_dir)
        
        # Ask platform questions
        question_scores = self.ask_platform_questions()
        
        # Generate recommendations
        recommendations = self.generate_recommendations(description_scores, file_scores, question_scores)
        
        # Display results
        print("\n🎯 Stack Recommendations")
        print("=" * 30)
        
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec.stack.upper()} (Score: {rec.score:.1f}, Confidence: {rec.confidence})")
            print(f"   Use Cases: {', '.join(rec.use_cases)}")
            print(f"   Reasoning: {', '.join(rec.reasoning)}")
        
        # Get user choice
        print("\nSelect your preferred stack:")
        for i in range(1, len(recommendations) + 1):
            print(f"{i}. {recommendations[i-1].stack.upper()}")
        
        choice = input("Enter choice: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(recommendations):
            selected_stack = recommendations[int(choice) - 1].stack
        else:
            selected_stack = recommendations[0].stack  # Default to top recommendation
        
        print(f"\n✅ Selected stack: {selected_stack.upper()}")
        return selected_stack, recommendations
    
    def detect_non_interactive(self, description: str) -> Tuple[str, List[StackRecommendation]]:
        """Run non-interactive stack detection for automation"""
        self.log(f"Non-interactive analysis of description: {description}")
        
        # Analyze description only (no file analysis or questions for automation)
        description_scores = self.analyze_description(description)
        file_scores = {}  # Skip file analysis for automation
        question_scores = {}  # Skip questions for automation
        
        # Generate recommendations
        recommendations = self.generate_recommendations(description_scores, file_scores, question_scores)
        
        # Return top recommendation
        if recommendations:
            selected_stack = recommendations[0].stack
            # Log reasoning to stderr for CI/CD debugging
            import sys
            print(f"Stack Detection: Selected {selected_stack.upper()} (Score: {recommendations[0].score:.1f})", file=sys.stderr)
            print(f"Reasoning: {', '.join(recommendations[0].reasoning)}", file=sys.stderr)
            return selected_stack, recommendations
        else:
            # Fallback to node.js if no recommendations
            print("Stack Detection: No clear match, falling back to node.js", file=sys.stderr)
            return "node", []

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Intelligent stack detection")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--description", help="Project description")
    
    args = parser.parse_args()
    
    detector = StackDetector(verbose=args.verbose)
    
    try:
        stack, recommendations = detector.detect_interactive(args.description)
        print(f"\n🎊 Recommended stack: {stack.upper()}")
        return stack
    except KeyboardInterrupt:
        print("\nStack detection cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during stack detection: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
