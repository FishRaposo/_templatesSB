#!/usr/bin/env python3
"""
Project Task Detection System

Analyzes project requirements and descriptions to:
1. Map requirements to existing tasks in the comprehensive 50-task system
2. Identify missing tasks that need to be created
3. Document new task requirements with proper metadata

Usage:
    python scripts/detect_project_tasks.py --description "project description"
    python scripts/detect_project_tasks.py --file project_requirements.txt
    python scripts/detect_project_tasks.py --interactive
    python scripts/detect_project_tasks.py --analyze-existing
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
import yaml

# Add the templates directory to the path
sys.path.append(str(Path(__file__).parent.parent))

try:
    from stack_config import get_all_stacks
except ImportError:
    from scripts.stack_config import get_all_stacks

STACK_ALIASES = {
    'nextjs': 'next',
    'agnostic': 'generic'
}

TIER_ALIASES = {
    'full': 'enterprise',
    'all': 'enterprise'
}

@dataclass
class TaskMatch:
    """Represents a matched task with confidence score"""
    task_id: str
    task_name: str
    description: str
    categories: List[str]
    confidence: float
    matched_keywords: List[str]
    tier: str = "core"
    
@dataclass
class MissingTask:
    """Represents a task that needs to be created"""
    suggested_name: str
    description: str
    categories: List[str]
    suggested_stacks: List[str]
    suggested_tier: str
    requirements: List[str]
    gap_reason: str
    priority: str = "medium"  # low, medium, high, critical

@dataclass
class StackRecommendation:
    """Represents a stack recommendation with confidence score"""
    primary_stack: str
    secondary_stack: Optional[str]
    confidence: float
    reasoning: List[str]
    use_case: str

class TaskDetectionSystem:
    """Main task detection and gap analysis system"""
    
    def __init__(self):
        self.tasks = self._load_task_index()
        self.keyword_mappings = self._build_keyword_mappings()
        self.category_keywords = self._build_category_keywords()
        self.stack_keywords = self._build_stack_keywords()

    def _canonical_stack(self, stack: str) -> str:
        return STACK_ALIASES.get(stack, stack)

    def _canonical_tier(self, tier: str) -> str:
        return TIER_ALIASES.get(tier, tier)
        
    def _load_task_index(self) -> Dict:
        """Load the comprehensive task index"""
        index_path = Path(__file__).parent.parent / "tasks" / "task-index.yaml"
        
        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data.get('tasks', {})  # Return only the tasks dict
        except Exception as e:
            print(f"Error loading task index: {e}")
            return {}
    
    def _build_keyword_mappings(self) -> Dict[str, List[str]]:
        """Build keyword to task mappings from existing tasks"""
        mappings = defaultdict(list)
        
        # Define comprehensive keyword patterns
        keyword_patterns = {
            # Web & API
            'api': ['api', 'rest', 'endpoint', 'service', 'backend'],
            'graphql': ['graphql', 'schema', 'resolver', 'query', 'mutation'],
            'web_scraping': ['scrape', 'scraping', 'crawl', 'parser', 'extract'],
            'dashboard': ['dashboard', 'admin', 'analytics', 'charts', 'tables'],
            'landing_page': ['landing', 'marketing', 'homepage', 'conversion'],
            'api_gateway': ['gateway', 'proxy', 'routing', 'middleware'],
            
            # Auth & Users
            'auth': ['auth', 'authentication', 'login', 'signin', 'password'],
            'oauth': ['oauth', 'google', 'github', 'social', 'sso'],
            'user_profile': ['profile', 'user', 'account', 'settings', 'avatar'],
            'billing': ['billing', 'payment', 'stripe', 'subscription', 'invoice'],
            'teams': ['team', 'organization', 'workspace', 'roles', 'permissions'],
            
            # Background & Automation
            'job_queue': ['queue', 'job', 'worker', 'background', 'async'],
            'scheduler': ['cron', 'schedule', 'periodic', 'cleanup', 'maintenance'],
            'notifications': ['notification', 'email', 'push', 'sms', 'alert'],
            'webhooks': ['webhook', 'integration', 'callback', 'event'],
            'file_processing': ['file', 'upload', 'processing', 'pipeline'],
            
            # Data & Analytics
            'etl': ['etl', 'extract', 'transform', 'load', 'pipeline'],
            'analytics': ['analytics', 'events', 'tracking', 'metrics'],
            'data_exploration': ['exploration', 'eda', 'analysis', 'visualization'],
            'forecasting': ['forecast', 'prediction', 'time series', 'trends'],
            'clustering': ['cluster', 'segmentation', ' grouping', 'classification'],
            'ab_testing': ['ab test', 'experiment', 'significance', 'conversion'],
            'embeddings': ['embedding', 'vector', 'search', 'semantic'],
            
            # SEO & Growth
            'seo_research': ['seo', 'keyword', 'research', 'serp', 'ranking'],
            'seo_audit': ['audit', 'seo', 'analysis', 'optimization'],
            'seo_tracking': ['rank', 'tracking', 'position', 'monitoring'],
            'content': ['content', 'brief', 'outline', 'generation'],
            'email_campaign': ['email', 'campaign', 'marketing', 'automation'],
            'link_monitoring': ['backlink', 'link', 'monitoring', 'health'],
            
            # Product & SaaS
            'crud': ['crud', 'create', 'read', 'update', 'delete'],
            'admin_panel': ['admin', 'management', 'control', 'superuser'],
            'feature_flags': ['feature flag', 'toggle', 'experiment', 'rollout'],
            'multitenancy': ['multi-tenant', 'tenant', 'workspace', 'isolation'],
            'audit_logging': ['audit', 'logging', 'history', 'trace'],
            
            # DevOps & Reliability
            'healthchecks': ['health', 'monitoring', 'uptime', 'metrics'],
            'ci': ['ci', 'cd', 'pipeline', 'build', 'deploy'],
            'error_reporting': ['error', 'logging', 'sentry', 'monitoring'],
            'config': ['config', 'environment', 'secrets', '12factor'],
            'canary': ['canary', 'rollout', 'deployment', 'staging'],
            
            # AI-Specific
            'llm_router': ['llm', 'prompt', 'model', 'routing'],
            'rag': ['rag', 'retrieval', 'embedding', 'knowledge'],
            'agents': ['agent', 'workflow', 'orchestration', 'automation'],
            'code_refactor': ['refactor', 'code', 'analysis', 'improvement'],
            
            # Meta & Tooling
            'bootstrap': ['bootstrap', 'scaffold', 'generator', 'template'],
            'docs': ['documentation', 'docs', 'site', 'wiki'],
            'sample_data': ['sample', 'fixture', 'fake', 'test data']
        }
        
        # Map keywords to actual tasks
        for task_id, task_data in self.tasks.items():
            for keyword_pattern, keywords in keyword_patterns.items():
                if any(keyword in task_id.lower() or 
                      keyword in task_data.get('description', '').lower() or
                      any(keyword in cat.lower() for cat in task_data.get('categories', []))
                      for keyword in keywords):
                    for keyword in keywords:
                        mappings[keyword].append(task_id)
        
        return dict(mappings)
    
    def _build_category_keywords(self) -> Dict[str, List[str]]:
        """Build category to keyword mappings"""
        return {
            'api': ['api', 'rest', 'endpoint', 'service', 'backend'],
            'frontend': ['frontend', 'ui', 'interface', 'web', 'app'],
            'auth': ['auth', 'authentication', 'security', 'login'],
            'data': ['data', 'database', 'storage', 'persistence'],
            'analytics': ['analytics', 'metrics', 'tracking', 'reporting'],
            'automation': ['automation', 'workflow', 'process', 'pipeline'],
            'ai': ['ai', 'ml', 'machine learning', 'intelligence'],
            'devops': ['devops', 'deployment', 'infrastructure', 'ops'],
            'seo': ['seo', 'search', 'optimization', 'ranking'],
            'content': ['content', 'cms', 'editor', 'publishing'],
            'billing': ['billing', 'payment', 'subscription', 'commerce'],
            'monitoring': ['monitoring', 'logging', 'health', 'metrics'],
            'testing': ['testing', 'test', 'quality', 'assurance'],
            'integration': ['integration', 'webhook', 'api', 'connect'],
            'security': ['security', 'auth', 'encryption', 'protection'],
            'performance': ['performance', 'optimization', 'speed', 'scaling'],
            'mobile': ['mobile', 'ios', 'android', 'app'],
            'search': ['search', 'index', 'query', 'filter'],
            'messaging': ['messaging', 'chat', 'notification', 'communication'],
            'file': ['file', 'upload', 'download', 'storage'],
            'email': ['email', 'mail', 'newsletter', 'campaign']
        }
    
    def _build_stack_keywords(self) -> Dict[str, List[str]]:
        """Build stack to keyword mappings"""
        return {
            'python': ['python', 'django', 'flask', 'fastapi', 'pandas'],
            'node': ['node', 'nodejs', 'express', 'javascript', 'typescript'],
            'go': ['go', 'golang', 'gorilla', 'gin'],
            'react': ['react', 'jsx', 'component', 'hooks'],
            'next': ['nextjs', 'next', 'ssr', 'static'],
            'flutter': ['flutter', 'dart', 'mobile', 'cross-platform'],
            'sql': ['sql', 'database', 'postgres', 'mysql', 'query'],
            'r': ['r', 'statistics', 'analysis', 'shiny'],
            'generic': ['agnostic', 'language', 'framework', 'platform', 'generic'],
            'typescript': ['typescript', 'ts'],
            'rust': ['rust', 'cargo'],
            'react_native': ['react native', 'reactnative', 'expo']
        }
    
    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract keywords from text using various patterns"""
        text = text.lower()
        
        # Extract individual words
        words = set(re.findall(r'\b[a-zA-Z]+\b', text))
        
        # Extract compound terms
        compound_terms = set()
        
        # Common compound patterns
        patterns = [
            r'\b(rest api|graphql api|web scraping|landing page|feature flag)\b',
            r'\b(ab test|a/b test|etl pipeline|job queue|email campaign)\b',
            r'\b(multi tenant|real time|machine learning|data science)\b',
            r'\b(error reporting|config management|canary release|health check)\b',
            r'\b(user profile|billing stripe|oauth integration|admin panel)\b',
            r'\b(seo audit|keyword research|rank tracker|content brief)\b',
            r'\b(llm prompt|rag pipeline|agentic workflow|code refactor)\b',
            r'\b(project bootstrap|docs site|sample data|crud module)\b',
            r'\b(react native)\b'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            compound_terms.update(matches)
        
        return words.union(compound_terms)
    
    def _calculate_base_confidence(self, task_id: str, keywords: Set[str], text: str) -> float:
        """Calculate base confidence score without complementary boost"""
        task_data = self.tasks.get(task_id, {})
        
        # Base confidence from keyword matching
        keyword_matches = 0
        total_keywords = len(keywords) if keywords else 1
        
        for keyword in keywords:
            if keyword in self.keyword_mappings:
                if task_id in self.keyword_mappings[keyword]:
                    keyword_matches += 1
        
        keyword_confidence = keyword_matches / total_keywords if total_keywords > 0 else 0
        
        # If no keyword matches, return 0 confidence to filter out noise
        if keyword_matches == 0:
            return 0.0
        
        # Boost confidence based on description similarity
        description = task_data.get('description', '').lower()
        text_lower = text.lower()
        
        # Simple text similarity boost
        common_words = set(description.split()) & set(text_lower.split())
        description_boost = len(common_words) / max(len(description.split()), 1) * 0.3
        
        # Category matching boost
        categories = task_data.get('categories', [])
        category_boost = 0
        for category in categories:
            if category in self.category_keywords:
                category_keywords = self.category_keywords[category]
                if any(keyword in text_lower for keyword in category_keywords):
                    category_boost += 0.15
        
        total_confidence = min(keyword_confidence + description_boost + category_boost, 1.0)
        
        return total_confidence
    
    def _calculate_task_confidence(self, task_id: str, keywords: Set[str], text: str) -> float:
        """Calculate confidence score for a task match with complementary boost"""
        base_confidence = self._calculate_base_confidence(task_id, keywords, text)
        
        if base_confidence == 0.0:
            return 0.0
        
        # Complementary task boost - if related tasks are detected, boost confidence
        text_lower = text.lower()
        complementary_boost = self._get_complementary_boost(task_id, keywords, text_lower)
        
        total_confidence = min(base_confidence + complementary_boost, 1.0)
        
        return total_confidence
    
    def _get_complementary_boost(self, task_id: str, keywords: Set[str], text_lower: str) -> float:
        """Get confidence boost based on complementary task detection"""
        # Define complementary task relationships
        complementary_groups = {
            'auth_group': ['auth-basic', 'auth-oauth', 'user-profile-management'],
            'api_group': ['rest-api-service', 'graphql-api', 'public-api-gateway'],
            'frontend_group': ['web-dashboard', 'landing-page'],
            'saas_group': ['billing-stripe', 'team-workspaces', 'feature-flags', 'multitenancy'],
            'background_group': ['job-queue', 'scheduled-tasks', 'notification-center'],
            'analytics_group': ['analytics-event-pipeline', 'data-exploration-report', 'forecasting-engine'],
            'seo_group': ['seo-keyword-research', 'seo-onpage-auditor', 'seo-rank-tracker'],
            'ai_group': ['llm-prompt-router', 'rag-pipeline', 'agentic-workflow']
        }
        
        boost = 0.0
        for group_name, group_tasks in complementary_groups.items():
            if task_id in group_tasks:
                # Check if other tasks in this group would also match
                matching_group_tasks = 0
                for other_task in group_tasks:
                    if other_task != task_id:
                        # Use base confidence to avoid recursion
                        other_confidence = self._calculate_base_confidence(other_task, keywords, text_lower)
                        if other_confidence > 0.1:
                            matching_group_tasks += 1
                
                # Boost if we have multiple related tasks
                if matching_group_tasks >= 1:
                    boost += 0.1 * matching_group_tasks
                break
        
        return boost
    
    def analyze_requirements(self, text: str, suggest_stacks: bool = False) -> Tuple[List[TaskMatch], List[MissingTask], Optional[StackRecommendation]]:
        """Analyze project requirements and return matched tasks and gaps"""
        keywords = self._extract_keywords(text)
        
        # Find matching tasks
        matched_tasks = []
        for task_id, task_data in self.tasks.items():
            confidence = self._calculate_task_confidence(task_id, keywords, text)
            if confidence > 0.1:  # Threshold for considering a match
                matched_keywords = [kw for kw in keywords if kw in self.keyword_mappings and task_id in self.keyword_mappings[kw]]
                
                match = TaskMatch(
                    task_id=task_id,
                    task_name=task_id.replace('-', ' ').title(),
                    description=task_data.get('description', ''),
                    categories=task_data.get('categories', []),
                    confidence=confidence,
                    matched_keywords=matched_keywords,
                    tier=self._canonical_tier(task_data.get('recommended_tier', {}).get('basic', 'core'))
                )
                matched_tasks.append(match)
        
        # Sort by confidence
        matched_tasks.sort(key=lambda x: x.confidence, reverse=True)
        
        # Identify gaps
        gaps = self._identify_gaps(text, keywords, matched_tasks)
        
        # Generate stack recommendation if requested
        stack_recommendation = None
        if suggest_stacks:
            stack_recommendation = self._recommend_stacks(matched_tasks, gaps, keywords, text)
        
        return matched_tasks, gaps, stack_recommendation
    
    def _recommend_stacks(self, matched_tasks: List[TaskMatch], gaps: List[MissingTask], keywords: Set[str], text: str) -> StackRecommendation:
        """Recommend optimal stacks based on detected requirements"""
        
        # Stack scoring based on detected tasks and requirements
        stack_scores = {stack: 0.0 for stack in get_all_stacks()}
        
        reasoning = []
        text_lower = text.lower()
        
        # Score based on matched tasks
        for task in matched_tasks:
            task_data = self.tasks.get(task.task_id, {})
            allowed_stacks = task_data.get('allowed_stacks', [])
            
            for stack in allowed_stacks:
                canonical_stack = self._canonical_stack(stack)
                if canonical_stack in stack_scores:
                    stack_scores[canonical_stack] += task.confidence * 2
        
        # Score based on gaps
        for gap in gaps:
            for stack in gap.suggested_stacks:
                canonical_stack = self._canonical_stack(stack)
                if canonical_stack in stack_scores:
                    stack_scores[canonical_stack] += 0.5  # Moderate boost for gap requirements
        
        # Score based on direct keyword mentions
        for keyword in keywords:
            for stack, stack_keywords in self.stack_keywords.items():
                if stack in stack_scores:
                    if keyword in stack_keywords:
                        stack_scores[stack] += 0.3
        
        # Apply use-case specific boosts
        if any(word in text_lower for word in ['real-time', 'websocket', 'chat', 'messaging']):
            stack_scores['node'] += 1.0
            reasoning.append("Node.js excels at real-time applications with WebSockets")
        
        if any(word in text_lower for word in ['mobile', 'ios', 'android', 'app']):
            stack_scores['flutter'] += 1.0
            reasoning.append("Flutter provides cross-platform mobile development")
        
        if any(word in text_lower for word in ['data science', 'machine learning', 'analytics', 'ml']):
            stack_scores['python'] += 1.0
            reasoning.append("Python has extensive data science and ML libraries")
        
        if any(word in text_lower for word in ['performance', 'scalability', 'high-throughput']):
            stack_scores['go'] += 0.8
            reasoning.append("Go offers excellent performance and concurrency")
        
        if any(word in text_lower for word in ['react', 'component', 'frontend', 'ui']):
            stack_scores['react'] += 0.8
            reasoning.append("React is ideal for component-based frontend applications")
        
        if any(word in text_lower for word in ['ssr', 'static', 'seo', 'marketing']):
            stack_scores['next'] += 0.8
            reasoning.append("Next.js provides SSR and SEO optimization")
        
        if any(word in text_lower for word in ['database', 'sql', 'query', 'postgres']):
            stack_scores['sql'] += 0.5
            reasoning.append("SQL database integration detected")
        
        if any(word in text_lower for word in ['statistics', 'research', 'analysis']):
            stack_scores['r'] += 0.6
            reasoning.append("R is strong for statistical analysis and research")
        
        # Find the best stack
        if not stack_scores:
            return StackRecommendation(
                primary_stack="python",
                secondary_stack="node",
                confidence=0.5,
                reasoning=["Default recommendation for general-purpose development"],
                use_case="General web application"
            )
        
        # Sort stacks by score
        sorted_stacks = sorted(stack_scores.items(), key=lambda x: x[1], reverse=True)
        
        primary_stack = sorted_stacks[0][0]
        primary_score = sorted_stacks[0][1]
        
        # Find secondary stack if there's a clear second choice
        secondary_stack = None
        if len(sorted_stacks) > 1 and sorted_stacks[1][1] > primary_score * 0.6:
            secondary_stack = sorted_stacks[1][0]
        
        # Calculate confidence
        max_possible_score = max(stack_scores.values()) + 1.0  # Normalize against max + boost
        confidence = min(primary_score / max_possible_score, 1.0)
        
        # Determine use case
        use_case = self._determine_use_case(matched_tasks, gaps, text_lower)
        
        # Add reasoning if empty
        if not reasoning:
            reasoning.append(f"Best match based on detected tasks and requirements")
        
        return StackRecommendation(
            primary_stack=primary_stack,
            secondary_stack=secondary_stack,
            confidence=confidence,
            reasoning=reasoning[:3],  # Top 3 reasons
            use_case=use_case
        )
    
    def _determine_use_case(self, matched_tasks: List[TaskMatch], gaps: List[MissingTask], text_lower: str) -> str:
        """Determine the primary use case based on detected requirements"""
        
        # Use case patterns
        use_cases = {
            "Real-time Application": ['real-time', 'websocket', 'chat', 'messaging', 'live'],
            "Mobile Application": ['mobile', 'ios', 'android', 'app'],
            "SaaS Platform": ['saas', 'billing', 'subscription', 'multi-tenant', 'teams'],
            "Data Analytics Platform": ['analytics', 'data', 'reporting', 'dashboard', 'metrics'],
            "API Service": ['api', 'rest', 'graphql', 'endpoint', 'service'],
            "E-commerce Platform": ['commerce', 'payment', 'billing', 'marketplace', 'shopping'],
            "Content Platform": ['content', 'cms', 'blog', 'publishing', 'seo'],
            "AI/ML Application": ['ai', 'ml', 'machine learning', 'llm', 'rag'],
            "Web Application": ['web', 'frontend', 'ui', 'application'],
            "Data Processing Pipeline": ['pipeline', 'etl', 'processing', 'batch', 'stream']
        }
        
        # Score each use case
        use_case_scores = {}
        for use_case, keywords in use_cases.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                use_case_scores[use_case] = score
        
        # Also check task categories
        task_categories = []
        for task in matched_tasks:
            task_categories.extend(task.categories)
        for gap in gaps:
            task_categories.extend(gap.categories)
        
        category_boosts = {
            "real-time": "Real-time Application",
            "mobile": "Mobile Application",
            "saas": "SaaS Platform",
            "analytics": "Data Analytics Platform",
            "api": "API Service",
            "billing": "E-commerce Platform",
            "content": "Content Platform",
            "ai": "AI/ML Application",
            "frontend": "Web Application",
            "data-processing": "Data Processing Pipeline"
        }
        
        for category in set(task_categories):
            if category in category_boosts:
                use_case = category_boosts[category]
                use_case_scores[use_case] = use_case_scores.get(use_case, 0) + 2
        
        if use_case_scores:
            return max(use_case_scores, key=use_case_scores.get)
        else:
            return "General Web Application"
    
    def _identify_gaps(self, text: str, keywords: Set[str], matched_tasks: List[TaskMatch]) -> List[MissingTask]:
        """Identify missing tasks based on unmet requirements"""
        gaps = []
        text_lower = text.lower()
        
        # Common gap patterns
        gap_patterns = [
            {
                'keywords': ['blockchain', 'crypto', 'web3', 'smart contract', 'nft'],
                'suggested_task': 'blockchain-integration',
                'description': 'Blockchain integration, smart contracts, Web3 connectivity',
                'categories': ['blockchain', 'web3', 'integration'],
                'stacks': ['python', 'node'],
                'tier': 'full',
                'requirements': ['Web3 wallet integration', 'Smart contract interaction', 'Transaction handling'],
                'priority': 'medium'
            },
            {
                'keywords': ['real-time', 'websocket', 'socket', 'live', 'streaming'],
                'suggested_task': 'real-time-websockets',
                'description': 'Real-time communication via WebSockets, live updates, streaming',
                'categories': ['real-time', 'communication', 'websockets'],
                'stacks': ['node', 'python', 'go'],
                'tier': 'core',
                'requirements': ['WebSocket server', 'Connection management', 'Live event broadcasting'],
                'priority': 'high'
            },
            {
                'keywords': ['search', 'elasticsearch', 'algolia', 'full-text', 'indexing'],
                'suggested_task': 'advanced-search',
                'description': 'Advanced search with Elasticsearch/Algolia, full-text, faceted search',
                'categories': ['search', 'indexing', 'analytics'],
                'stacks': ['python', 'node', 'go'],
                'tier': 'core',
                'requirements': ['Search index setup', 'Query optimization', 'Faceted search', 'Analytics'],
                'priority': 'medium'
            },
            {
                'keywords': ['cache', 'redis', 'memcached', 'caching', 'performance'],
                'suggested_task': 'caching-layer',
                'description': 'Multi-layer caching with Redis/Memcached, invalidation strategies',
                'categories': ['performance', 'caching', 'infrastructure'],
                'stacks': ['python', 'node', 'go'],
                'tier': 'core',
                'requirements': ['Cache configuration', 'Invalidation strategies', 'Performance monitoring'],
                'priority': 'medium'
            },
            {
                'keywords': ['forum', 'community', 'discussion', 'comments', 'threads'],
                'suggested_task': 'community-forum',
                'description': 'Community forum with discussions, threads, moderation, user interactions',
                'categories': ['community', 'social', 'discussion'],
                'stacks': ['node', 'python', 'react'],
                'tier': 'core',
                'requirements': ['Thread management', 'User permissions', 'Moderation tools', 'Notifications'],
                'priority': 'low'
            },
            {
                'keywords': ['marketplace', 'listing', 'vendor', 'booking', 'reservation'],
                'suggested_task': 'marketplace-platform',
                'description': 'Marketplace platform with listings, vendors, bookings, payments',
                'categories': ['marketplace', 'commerce', 'booking'],
                'stacks': ['node', 'python', 'react'],
                'tier': 'full',
                'requirements': ['Listing management', 'Vendor profiles', 'Booking system', 'Payment integration'],
                'priority': 'medium'
            },
            {
                'keywords': ['chat', 'messaging', 'real-time', 'conversation', 'im'],
                'suggested_task': 'chat-messaging',
                'description': 'Real-time chat and messaging system with rooms, direct messages',
                'categories': ['messaging', 'real-time', 'communication'],
                'stacks': ['node', 'python', 'react', 'flutter'],
                'tier': 'core',
                'requirements': ['Real-time messaging', 'Room management', 'Message history', 'Online status'],
                'priority': 'medium'
            },
            {
                'keywords': ['workflow', 'approval', 'process', 'automation', 'business'],
                'suggested_task': 'workflow-automation',
                'description': 'Business workflow automation with approval chains, process management',
                'categories': ['workflow', 'automation', 'business'],
                'stacks': ['node', 'python'],
                'tier': 'full',
                'requirements': ['Process designer', 'Approval chains', 'Task assignment', 'Progress tracking'],
                'priority': 'medium'
            },
            {
                'keywords': ['mobile', 'ios', 'android', 'app', 'native'],
                'suggested_task': 'mobile-app-scaffold',
                'description': 'Native mobile app scaffold with navigation, state management, API integration',
                'categories': ['mobile', 'app', 'scaffold'],
                'stacks': ['flutter'],
                'tier': 'core',
                'requirements': ['Navigation structure', 'State management', 'API integration', 'Platform-specific features'],
                'priority': 'medium'
            },
            {
                'keywords': ['video', 'streaming', 'media', 'upload', 'processing'],
                'suggested_task': 'video-streaming',
                'description': 'Video upload, processing, streaming, and management system',
                'categories': ['video', 'media', 'streaming'],
                'stacks': ['python', 'node'],
                'tier': 'full',
                'requirements': ['Video upload', 'Transcoding', 'Streaming delivery', 'Thumbnail generation'],
                'priority': 'low'
            }
        ]
        
        # Check for gap patterns
        matched_task_ids = {match.task_id for match in matched_tasks}
        
        for pattern in gap_patterns:
            if any(keyword in text_lower for keyword in pattern['keywords']):
                # Check if this gap is already covered by existing tasks
                if not any(pattern['suggested_task'] in existing_id for existing_id in matched_task_ids):
                    gap = MissingTask(
                        suggested_name=pattern['suggested_task'],
                        description=pattern['description'],
                        categories=pattern['categories'],
                        suggested_stacks=[self._canonical_stack(s) for s in pattern['stacks']],
                        suggested_tier=self._canonical_tier(pattern['tier']),
                        requirements=pattern['requirements'],
                        gap_reason=f"Detected keywords: {', '.join(pattern['keywords'])}",
                        priority=pattern['priority']
                    )
                    gaps.append(gap)
        
        # Additional gap detection based on unmatched high-value keywords
        high_value_keywords = {
            'blockchain': 'blockchain-integration',
            'web3': 'blockchain-integration',
            'smart contract': 'blockchain-integration',
            'real-time': 'real-time-websockets',
            'websocket': 'real-time-websockets',
            'streaming': 'real-time-websockets',
            'elasticsearch': 'advanced-search',
            'algolia': 'advanced-search',
            'full-text search': 'advanced-search',
            'redis': 'caching-layer',
            'memcached': 'caching-layer',
            'forum': 'community-forum',
            'marketplace': 'marketplace-platform',
            'booking': 'marketplace-platform',
            'chat': 'chat-messaging',
            'messaging': 'chat-messaging',
            'workflow': 'workflow-automation',
            'approval': 'workflow-automation',
            'mobile app': 'mobile-app-scaffold',
            'native app': 'mobile-app-scaffold',
            'video': 'video-streaming',
            'media processing': 'video-streaming'
        }
        
        for keyword, task_name in high_value_keywords.items():
            if keyword in text_lower and not any(task_name in existing_id for existing_id in matched_task_ids):
                if not any(gap.suggested_name == task_name for gap in gaps):
                    # Find the pattern for this task
                    pattern = next((p for p in gap_patterns if p['suggested_task'] == task_name), None)
                    if pattern:
                        gap = MissingTask(
                            suggested_name=pattern['suggested_task'],
                            description=pattern['description'],
                            categories=pattern['categories'],
                            suggested_stacks=[self._canonical_stack(s) for s in pattern['stacks']],
                            suggested_tier=self._canonical_tier(pattern['tier']),
                            requirements=pattern['requirements'],
                            gap_reason=f"Detected high-value keyword: '{keyword}'",
                            priority=pattern['priority']
                        )
                        gaps.append(gap)
        
        return gaps
    
    def generate_task_template(self, missing_task: MissingTask) -> str:
        """Generate a task template for a missing task"""
        template = f"""# {missing_task.suggested_name.replace('-', ' ').title()}

## Description
{missing_task.description}

## Categories
{', '.join([f'- {cat}' for cat in missing_task.categories])}

## Recommended Stacks
{', '.join([f'- {stack}' for stack in missing_task.suggested_stacks])}

## Recommended Tier
{missing_task.suggested_tier}

## Requirements
{chr(10).join([f'- [ ] {req}' for req in missing_task.requirements])}

## Gap Analysis
**Reason for Addition**: {missing_task.gap_reason}
**Priority**: {missing_task.priority}

## Implementation Notes
This task was identified as a gap in the comprehensive task system based on project requirements analysis.

## Suggested File Structure
```
tasks/{missing_task.suggested_name}/
├── meta.yaml
├── universal/
│   ├── code/
│   │   └── {missing_task.suggested_name.upper()}-SKELETON.tpl.md
│   ├── tests/
│   │   └── test-{missing_task.suggested_name}.tpl.md
│   └── docs/
│       └── {missing_task.suggested_name}.tpl.md
└── stacks/
    ├── python/
    │   └── base/
    │       └── code/
    │           └── service.tpl.py
    ├── node/
    │   └── base/
    │       └── code/
    │           └── service.tpl.js
    └── go/
        └── base/
            └── code/
                └── service.tpl.go
```

## Integration Steps
1. Create task directory structure using scaffolding
2. Implement universal templates with tier-specific features
3. Add stack-specific implementations
4. Generate file mappings and integrate with resolver
5. Test with target stacks and tiers
"""
        return template
    
    def interactive_analysis(self) -> Tuple[List[TaskMatch], List[MissingTask], Optional[StackRecommendation]]:
        """Run interactive analysis with user input"""
        print("=== Project Task Detection System ===")
        print("Answer the following questions to analyze your project requirements:\n")
        
        questions = [
            "What type of project are you building? (e.g., web app, mobile app, API, data platform)",
            "What are the main features you need? (e.g., user authentication, data processing, real-time updates)",
            "What technologies are you planning to use? (e.g., React, Python, PostgreSQL)",
            "Do you need any of the following? (comma-separated: user management, billing, analytics, search, notifications)",
            "Are there any specific integrations required? (e.g., Stripe, Google Auth, Elasticsearch)",
            "What's your expected scale? (small prototype, production service, enterprise system)"
        ]
        
        answers = []
        for i, question in enumerate(questions, 1):
            answer = input(f"{i}. {question}\n> ").strip()
            answers.append(answer)
        
        # Combine all answers into analysis text
        analysis_text = " ".join(answers)
        print(f"\nAnalyzing requirements...")
        
        # Ask if user wants stack recommendations
        suggest_stacks = input("Would you like stack recommendations? (y/n): ").lower().startswith('y')
        
        return self.analyze_requirements(analysis_text, suggest_stacks)
    
    def analyze_existing_projects(self) -> Dict[str, Tuple[List[TaskMatch], List[MissingTask]]]:
        """Analyze existing project files in the workspace"""
        results = {}
        
        # Look for project files
        workspace_root = Path(__file__).parent.parent.parent
        project_patterns = [
            "**/*.md",
            "**/*.txt", 
            "**/README*",
            "**/requirements*.txt",
            "**/package.json",
            "**/pyproject.toml"
        ]
        
        for pattern in project_patterns:
            for file_path in workspace_root.glob(pattern):
                if file_path.is_file() and file_path.stat().st_size < 100000:  # Skip large files
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        if len(content.strip()) > 50:  # Skip very short files
                            matched_tasks, gaps = self.analyze_requirements(content)
                            if matched_tasks or gaps:
                                results[str(file_path.relative_to(workspace_root))] = (matched_tasks, gaps)
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
        
        return results

def main():
    """Main entry point"""
    
    # Import prompt validation
    try:
        from prompt_validator import PromptValidator, ValidationLevel
    except ImportError:
        print("❌ ERROR: Prompt validation is required for security")
        print("Please ensure prompt_validator.py is available in the scripts directory")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Project Task Detection System")
    parser.add_argument("--description", help="Project description to analyze")
    parser.add_argument("--file", help="File containing project requirements")
    parser.add_argument("--interactive", action="store_true", help="Run interactive analysis")
    parser.add_argument("--analyze-existing", action="store_true", help="Analyze existing project files")
    parser.add_argument("--suggest-stacks", action="store_true", help="Include stack recommendations")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--generate-templates", action="store_true", help="Generate task templates for gaps")
    parser.add_argument("--min-confidence", type=float, default=0.2, help="Minimum confidence threshold")
    
    args = parser.parse_args()
    
    # Validate all inputs before processing
    validator = PromptValidator(ValidationLevel.STANDARD)
    
    # Validate project description if provided
    if args.description:
        desc_result = validator.validate_project_description(args.description)
        if not desc_result.is_valid:
            print("❌ Project description validation failed:")
            for error in desc_result.errors:
                print(f"   - {error}")
            sys.exit(1)
        
        # Show warnings if any
        if desc_result.warnings:
            print("⚠️  Project description warnings:")
            for warning in desc_result.warnings:
                print(f"   - {warning}")
            print()
    
    # Validate output file if provided
    if args.output:
        args_dict = {'output': args.output}
        output_result = validator.validate_cli_arguments(args_dict)
        if not output_result.is_valid:
            print("❌ Output file validation failed:")
            for error in output_result.errors:
                print(f"   - {error}")
            sys.exit(1)
    
    detector = TaskDetectionSystem()
    
    if args.interactive:
        matched_tasks, gaps, stack_recommendation = detector.interactive_analysis()
    elif args.analyze_existing:
        results = detector.analyze_existing_projects()
        print("\n=== Existing Project Analysis ===")
        for file_path, (tasks, gaps) in results.items():
            print(f"\n📁 {file_path}")
            if tasks:
                print(f"  ✅ Matched {len(tasks)} tasks:")
                for task in tasks[:3]:  # Show top 3
                    print(f"    - {task.task_name} (confidence: {task.confidence:.2f})")
            if gaps:
                print(f"  ⚠️  Found {len(gaps)} potential gaps:")
                for gap in gaps[:2]:  # Show top 2
                    print(f"    - {gap.suggested_name} (priority: {gap.priority})")
        return
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
            matched_tasks, gaps, stack_recommendation = detector.analyze_requirements(text, args.suggest_stacks)
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    elif args.description:
        matched_tasks, gaps, stack_recommendation = detector.analyze_requirements(args.description, args.suggest_stacks)
    else:
        parser.print_help()
        return
    
    # Filter by confidence threshold
    matched_tasks = [task for task in matched_tasks if task.confidence >= args.min_confidence]
    
    # Display results
    print("\n=== Task Detection Results ===")
    
    print(f"\n✅ Found {len(matched_tasks)} matching tasks:")
    for i, task in enumerate(matched_tasks, 1):
        print(f"\n{i}. {task.task_name} (confidence: {task.confidence:.2f})")
        print(f"   Description: {task.description}")
        print(f"   Categories: {', '.join(task.categories)}")
        print(f"   Matched keywords: {', '.join(task.matched_keywords)}")
        print(f"   Recommended tier: {task.tier}")
    
    # Display stack recommendation if available
    if stack_recommendation:
        print(f"\n🎯 Stack Recommendation:")
        print(f"   Primary Stack: {stack_recommendation.primary_stack}")
        if stack_recommendation.secondary_stack:
            print(f"   Secondary Stack: {stack_recommendation.secondary_stack}")
        print(f"   Confidence: {stack_recommendation.confidence:.2f}")
        print(f"   Use Case: {stack_recommendation.use_case}")
        print(f"   Reasoning:")
        for reason in stack_recommendation.reasoning:
            print(f"     - {reason}")
    
    print(f"\n⚠️  Found {len(gaps)} potential task gaps:")
    for i, gap in enumerate(gaps, 1):
        print(f"\n{i}. {gap.suggested_name} (priority: {gap.priority})")
        print(f"   Description: {gap.description}")
        print(f"   Categories: {', '.join(gap.categories)}")
        print(f"   Suggested stacks: {', '.join(gap.suggested_stacks)}")
        print(f"   Suggested tier: {gap.suggested_tier}")
        print(f"   Gap reason: {gap.gap_reason}")
        print(f"   Requirements:")
        for req in gap.requirements:
            print(f"     - {req}")
    
    # Generate templates if requested
    if args.generate_templates and gaps:
        print(f"\n📝 Generating task templates...")
        templates_dir = Path(__file__).parent.parent / "docs" / "task-gap-templates"
        templates_dir.mkdir(exist_ok=True)
        
        for gap in gaps:
            template_content = detector.generate_task_template(gap)
            template_file = templates_dir / f"{gap.suggested_name}.md"
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(template_content)
            print(f"   Generated: {template_file}")
    
    # Save results to file if requested
    if args.output:
        results = {
            'matched_tasks': [asdict(task) for task in matched_tasks],
            'gaps': [asdict(gap) for gap in gaps],
            'stack_recommendation': asdict(stack_recommendation) if stack_recommendation else None,
            'analysis_metadata': {
                'min_confidence': args.min_confidence,
                'suggest_stacks': args.suggest_stacks,
                'total_tasks_analyzed': len(detector.tasks),
                'timestamp': str(Path(__file__).stat().st_mtime)
            }
        }
        
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()
