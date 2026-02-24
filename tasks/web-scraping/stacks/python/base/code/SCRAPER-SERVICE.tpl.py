"""
File: SCRAPER-SERVICE.tpl.py
Purpose: Template for web-scraping implementation
Generated for: {{PROJECT_NAME}}
"""

# -----------------------------------------------------------------------------
# FILE: SCRAPER-SERVICE.tpl.py
# PURPOSE: Production-ready web scraping service with async processing, rate limiting, and error handling
# USAGE: Import and adapt for web scraping functionality in Python projects
# AUTHOR: {{AUTHOR}}
# VERSION: {{VERSION}}
# SINCE: {{VERSION}}
# -----------------------------------------------------------------------------

"""
{{PROJECT_NAME}} - Web Scraping Service
Production-ready web scraping service with async processing, rate limiting, and error handling.

This service provides a comprehensive framework for extracting data from websites
with built-in politeness policies, retry logic, and data persistence.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

import asyncio
import logging
import hashlib
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import aiohttp
import requests
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete

from {{PROJECT_NAME}}.core.config import get_settings
from {{PROJECT_NAME}}.core.database import get_async_session
from {{PROJECT_NAME}}.core.logging import get_logger
from {{PROJECT_NAME}}.core.exceptions import ScrapingError, RateLimitError, ValidationError

logger = get_logger(__name__)

@dataclass
class ScrapingRequest:
    """Represents a scraping request with all necessary parameters."""
    url: str
    selectors: Dict[str, str]
    options: Dict[str, Any]
    priority: int = 5
    retry_count: int = 0
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

@dataclass
class ScrapingResult:
    """Represents the result of a scraping operation."""
    url: str
    success: bool
    data: Dict[str, Any]
    metadata: Dict[str, Any]
    error: Optional[str] = None
    scraped_at: datetime = None
    
    def __post_init__(self):
        if self.scraped_at is None:
            self.scraped_at = datetime.utcnow()

@dataclass
class DomainStats:
    """Tracks scraping statistics per domain."""
    domain: str
    requests_per_second: float
    last_request_time: datetime
    total_requests: int
    error_rate: float
    blocked: bool = False

class RateLimiter:
    """Implements rate limiting and robots.txt compliance."""
    
    def __init__(self, default_rate: float = 1.0):
        self.default_rate = default_rate
        self.domain_rates: Dict[str, float] = {}
        self.domain_stats: Dict[str, DomainStats] = {}
        self.robots_cache: Dict[str, RobotFileParser] = {}
        self.request_times: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
    
    async def can_make_request(self, url: str) -> bool:
        """Check if a request can be made to the given URL."""
        domain = urlparse(url).netloc
        
        async with self._lock:
            # Check robots.txt compliance
            if not await self._check_robots_txt(url):
                logger.warning(f"Robots.txt disallows scraping: {url}")
                return False
            
            # Check rate limiting
            if not self._check_rate_limit(domain):
                logger.debug(f"Rate limit exceeded for domain: {domain}")
                return False
            
            # Check if domain is blocked
            stats = self.domain_stats.get(domain)
            if stats and stats.blocked:
                logger.warning(f"Domain {domain} is blocked due to high error rate")
                return False
            
            return True
    
    async def wait_for_slot(self, url: str) -> None:
        """Wait until a request slot is available for the given URL."""
        domain = urlparse(url).netloc
        rate = self.domain_rates.get(domain, self.default_rate)
        
        while not await self.can_make_request(url):
            await asyncio.sleep(1.0 / rate)
    
    async def record_request(self, url: str, success: bool) -> None:
        """Record a request attempt and update statistics."""
        domain = urlparse(url).netloc
        now = time.time()
        
        async with self._lock:
            # Update request times for rate limiting
            if domain not in self.request_times:
                self.request_times[domain] = []
            
            self.request_times[domain].append(now)
            
            # Clean old request times (keep last 10 minutes)
            cutoff = now - 600
            self.request_times[domain] = [
                t for t in self.request_times[domain] if t > cutoff
            ]
            
            # Update domain statistics
            if domain not in self.domain_stats:
                self.domain_stats[domain] = DomainStats(
                    domain=domain,
                    requests_per_second=0.0,
                    last_request_time=datetime.utcnow(),
                    total_requests=0,
                    error_rate=0.0
                )
            
            stats = self.domain_stats[domain]
            stats.total_requests += 1
            stats.last_request_time = datetime.utcnow()
            
            # Calculate requests per second
            recent_requests = len(self.request_times[domain])
            stats.requests_per_second = recent_requests / 600.0  # 10-minute window
            
            # Update error rate
            if not success:
                stats.error_rate = (stats.error_rate * (stats.total_requests - 1) + 1.0) / stats.total_requests
                
                # Block domain if error rate is too high
                if stats.error_rate > 0.5 and stats.total_requests > 10:
                    stats.blocked = True
                    logger.error(f"Blocking domain {domain} due to high error rate: {stats.error_rate:.2%}")
            else:
                stats.error_rate = (stats.error_rate * (stats.total_requests - 1)) / stats.total_requests
                
                # Unblock domain if error rate improves
                if stats.blocked and stats.error_rate < 0.1:
                    stats.blocked = False
                    logger.info(f"Unblocking domain {domain} as error rate improved: {stats.error_rate:.2%}")
    
    async def _check_robots_txt(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        domain = urlparse(url).netloc
        
        # Get or cache robots.txt parser
        if domain not in self.robots_cache:
            robots_url = f"https://{domain}/robots.txt"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            robots_text = await response.text()
                            parser = RobotFileParser()
                            parser.set_url(robots_url)
                            parser.parse(robots_text.splitlines())
                            self.robots_cache[domain] = parser
                        else:
                            # No robots.txt or error, assume allowed
                            self.robots_cache[domain] = None
            except Exception as e:
                logger.warning(f"Failed to fetch robots.txt for {domain}: {e}")
                self.robots_cache[domain] = None
        
        parser = self.robots_cache.get(domain)
        if parser is None:
            return True  # No robots.txt, assume allowed
        
        user_agent = get_settings().SCRAPER_USER_AGENT
        return parser.can_fetch(user_agent, url)
    
    def _check_rate_limit(self, domain: str) -> bool:
        """Check if rate limit allows a request to the domain."""
        if domain not in self.request_times:
            return True
        
        rate = self.domain_rates.get(domain, self.default_rate)
        now = time.time()
        
        # Count requests in the last second
        recent_requests = [
            t for t in self.request_times[domain] 
            if now - t < 1.0
        ]
        
        return len(recent_requests) < rate

class ContentParser:
    """Handles content parsing and data extraction."""
    
    def __init__(self):
        self.parsers = {
            'html': self._parse_html,
            'json': self._parse_json,
            'xml': self._parse_xml,
            'text': self._parse_text
        }
    
    async def parse(self, content: str, content_type: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Parse content and extract data using selectors."""
        parser_func = self.parsers.get(content_type.lower(), self._parse_html)
        return await parser_func(content, selectors)
    
    async def _parse_html(self, html: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Parse HTML content using CSS selectors."""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            result = {}
            
            for field, selector in selectors.items():
                elements = soup.select(selector)
                if len(elements) == 1:
                    result[field] = elements[0].get_text(strip=True)
                elif len(elements) > 1:
                    result[field] = [elem.get_text(strip=True) for elem in elements]
                else:
                    result[field] = None
            
            return result
        except Exception as e:
            raise ScrapingError(f"HTML parsing failed: {e}")
    
    async def _parse_json(self, json_str: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Parse JSON content using JSONPath-like selectors."""
        try:
            import json
            data = json.loads(json_str)
            result = {}
            
            for field, path in selectors.items():
                keys = path.split('.')
                value = data
                try:
                    for key in keys:
                        if isinstance(value, dict):
                            value = value.get(key)
                        elif isinstance(value, list) and key.isdigit():
                            value = value[int(key)]
                        else:
                            value = None
                            break
                    result[field] = value
                except (KeyError, IndexError, TypeError):
                    result[field] = None
            
            return result
        except Exception as e:
            raise ScrapingError(f"JSON parsing failed: {e}")
    
    async def _parse_xml(self, xml: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Parse XML content using XPath selectors."""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            result = {}
            
            for field, xpath in selectors.items():
                elements = root.findall(xpath)
                if len(elements) == 1:
                    result[field] = elements[0].text
                elif len(elements) > 1:
                    result[field] = [elem.text for elem in elements]
                else:
                    result[field] = None
            
            return result
        except Exception as e:
            raise ScrapingError(f"XML parsing failed: {e}")
    
    async def _parse_text(self, text: str, selectors: Dict[str, str]) -> Dict[str, Any]:
        """Parse plain text content using regex patterns."""
        import re
        result = {}
        
        for field, pattern in selectors.items():
            try:
                matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
                if len(matches) == 1:
                    result[field] = matches[0]
                elif len(matches) > 1:
                    result[field] = matches
                else:
                    result[field] = None
            except re.error as e:
                raise ScrapingError(f"Regex pattern error for field {field}: {e}")
        
        return result

class ScrapingService:
    """Main scraping service orchestrator."""
    
    def __init__(self):
        self.settings = get_settings()
        self.rate_limiter = RateLimiter(
            default_rate=self.settings.SCRAPER_RATE_LIMIT
        )
        self.parser = ContentParser()
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_queue: asyncio.Queue = asyncio.Queue()
        self.results: Dict[str, ScrapingResult] = {}
        self._workers: List[asyncio.Task] = []
        self._running = False
    
    async def start(self, num_workers: int = 5) -> None:
        """Start the scraping service with specified number of workers."""
        if self._running:
            logger.warning("Scraping service is already running")
            return
        
        self._running = True
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.settings.SCRAPER_TIMEOUT),
            headers={'User-Agent': self.settings.SCRAPER_USER_AGENT}
        )
        
        # Start worker coroutines
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self._workers.append(worker)
        
        logger.info(f"Started scraping service with {num_workers} workers")
    
    async def stop(self) -> None:
        """Stop the scraping service and cleanup resources."""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel all workers
        for worker in self._workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self._workers, return_exceptions=True)
        
        # Close session
        if self.session:
            await self.session.close()
        
        logger.info("Stopped scraping service")
    
    async def scrape_url(self, url: str, selectors: Dict[str, str], **options) -> ScrapingResult:
        """Scrape a single URL and return the result."""
        request = ScrapingRequest(
            url=url,
            selectors=selectors,
            options=options
        )
        
        return await self._scrape_request(request)
    
    async def scrape_urls(self, urls: List[Dict[str, Any]]) -> List[ScrapingResult]:
        """Scrape multiple URLs concurrently."""
        requests = []
        for url_config in urls:
            request = ScrapingRequest(
                url=url_config['url'],
                selectors=url_config['selectors'],
                options=url_config.get('options', {}),
                priority=url_config.get('priority', 5)
            )
            requests.append(request)
        
        # Add to queue
        for request in requests:
            await self.request_queue.put(request)
        
        # Wait for all to complete
        results = []
        for request in requests:
            # Wait for result (simplified - in production, use futures)
            while request.url not in self.results:
                await asyncio.sleep(0.1)
            results.append(self.results[request.url])
            del self.results[request.url]
        
        return results
    
    async def _worker(self, worker_id: str) -> None:
        """Worker coroutine that processes scraping requests."""
        logger.info(f"Started worker: {worker_id}")
        
        while self._running:
            try:
                # Get request from queue
                request = await asyncio.wait_for(
                    self.request_queue.get(), 
                    timeout=1.0
                )
                
                # Process request
                result = await self._scrape_request(request)
                
                # Store result
                self.results[request.url] = result
                
                logger.debug(f"{worker_id} completed scraping: {request.url}")
                
            except asyncio.TimeoutError:
                continue  # No requests available, continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
        
        logger.info(f"Stopped worker: {worker_id}")
    
    async def _scrape_request(self, request: ScrapingRequest) -> ScrapingResult:
        """Process a single scraping request."""
        max_retries = request.options.get('retry_attempts', self.settings.SCRAPER_RETRY_ATTEMPTS)
        
        for attempt in range(max_retries + 1):
            try:
                # Wait for rate limiting
                await self.rate_limiter.wait_for_slot(request.url)
                
                # Make HTTP request
                content, content_type = await self._fetch_content(request.url)
                
                # Parse content
                data = await self.parser.parse(content, content_type, request.selectors)
                
                # Validate data
                self._validate_data(data, request.selectors)
                
                # Create successful result
                result = ScrapingResult(
                    url=request.url,
                    success=True,
                    data=data,
                    metadata={
                        'content_type': content_type,
                        'content_length': len(content),
                        'scrape_time': datetime.utcnow().isoformat(),
                        'attempt': attempt + 1
                    }
                )
                
                # Record successful request
                await self.rate_limiter.record_request(request.url, True)
                
                return result
                
            except Exception as e:
                logger.warning(f"Scraping attempt {attempt + 1} failed for {request.url}: {e}")
                
                # Record failed request
                await self.rate_limiter.record_request(request.url, False)
                
                # If this is the last attempt, return failure result
                if attempt == max_retries:
                    result = ScrapingResult(
                        url=request.url,
                        success=False,
                        data={},
                        metadata={'attempt': attempt + 1},
                        error=str(e)
                    )
                    return result
                
                # Wait before retry (exponential backoff)
                delay = min(2 ** attempt, 30)  # Max 30 seconds
                await asyncio.sleep(delay)
    
    async def _fetch_content(self, url: str) -> tuple[str, str]:
        """Fetch content from URL and return content with content type."""
        if not self.session:
            raise ScrapingError("Scraping service not started")
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise ScrapingError(f"HTTP {response.status}: {url}")
                
                content = await response.text()
                content_type = response.headers.get('content-type', 'text/html').split(';')[0]
                
                return content, content_type
                
        except aiohttp.ClientError as e:
            raise ScrapingError(f"Network error: {e}")
    
    def _validate_data(self, data: Dict[str, Any], selectors: Dict[str, str]) -> None:
        """Validate extracted data against expected selectors."""
        if not data:
            raise ValidationError("No data extracted")
        
        # Check if required fields are present and not None
        required_fields = selectors.keys()
        missing_fields = [field for field in required_fields if data.get(field) is None]
        
        if missing_fields:
            logger.warning(f"Missing fields for {selectors}: {missing_fields}")
            # Don't raise error for missing fields, just log warning
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scraping service statistics."""
        return {
            'running': self._running,
            'workers': len(self._workers),
            'queue_size': self.request_queue.qsize(),
            'domain_stats': {domain: asdict(stats) for domain, stats in self.rate_limiter.domain_stats.items()}
        }

# Global service instance
_scraping_service: Optional[ScrapingService] = None

def get_scraping_service() -> ScrapingService:
    """Get the global scraping service instance."""
    global _scraping_service
    if _scraping_service is None:
        _scraping_service = ScrapingService()
    return _scraping_service

# Convenience functions for common operations
async def scrape_url(url: str, selectors: Dict[str, str], **options) -> ScrapingResult:
    """Convenience function to scrape a single URL."""
    service = get_scraping_service()
    return await service.scrape_url(url, selectors, **options)

async def scrape_urls(urls: List[Dict[str, Any]]) -> List[ScrapingResult]:
    """Convenience function to scrape multiple URLs."""
    service = get_scraping_service()
    return await service.scrape_urls(urls)

# Lifecycle management
async def start_scraping_service(num_workers: int = 5) -> None:
    """Start the global scraping service."""
    service = get_scraping_service()
    await service.start(num_workers)

async def stop_scraping_service() -> None:
    """Stop the global scraping service."""
    service = get_scraping_service()
    await service.stop()
