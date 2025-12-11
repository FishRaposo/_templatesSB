# Universal Template System - Python Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: python
# Category: testing

# -----------------------------------------------------------------------------
# FILE: TEST_SCRAPER.tpl.py
# PURPOSE: Test suite for web scraping service functionality
# USAGE: Import and adapt for testing web scraping in Python projects
# AUTHOR: {{AUTHOR}}
# VERSION: {{VERSION}}
# SINCE: {{VERSION}}
# -----------------------------------------------------------------------------

"""
{{PROJECT_NAME}} - Web Scraping Service Tests
Test suite for the web scraping functionality.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from datetime import datetime

from {{PROJECT_NAME}}.tasks.web_scraping.service import (
    ScrapingService, 
    RateLimiter, 
    ContentParser,
    ScrapingRequest,
    ScrapingResult,
    scrape_url,
    scrape_urls
)

class TestRateLimiter:
    """Test rate limiting functionality."""
    
    @pytest.fixture
    def rate_limiter(self):
        return RateLimiter(default_rate=2.0)
    
    @pytest.mark.asyncio
    async def test_can_make_request(self, rate_limiter):
        """Test basic rate limiting permission."""
        # Should allow first request
        assert await rate_limiter.can_make_request("https://example.com")
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self, rate_limiter):
        """Test that rate limits are enforced."""
        url = "https://example.com"
        
        # Make multiple requests quickly
        for i in range(3):
            allowed = await rate_limiter.can_make_request(url)
            if i < 2:  # First 2 should be allowed
                assert allowed
            else:  # Third should be rate limited
                assert not allowed
    
    @pytest.mark.asyncio
    async def test_record_request_updates_stats(self, rate_limiter):
        """Test that recording requests updates statistics."""
        url = "https://example.com"
        
        await rate_limiter.record_request(url, success=True)
        stats = rate_limiter.domain_stats.get("example.com")
        
        assert stats is not None
        assert stats.total_requests == 1
        assert stats.error_rate == 0.0

class TestContentParser:
    """Test content parsing functionality."""
    
    @pytest.fixture
    def parser(self):
        return ContentParser()
    
    @pytest.mark.asyncio
    async def test_html_parsing(self, parser):
        """Test HTML content parsing."""
        html = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <h1 class="title">Main Title</h1>
                <div class="content">Content here</div>
                <ul>
                    <li class="item">Item 1</li>
                    <li class="item">Item 2</li>
                </ul>
            </body>
        </html>
        """
        
        selectors = {
            'title': 'title',
            'main_title': 'h1.title',
            'content': 'div.content',
            'items': 'li.item'
        }
        
        result = await parser.parse(html, 'html', selectors)
        
        assert result['title'] == 'Test Page'
        assert result['main_title'] == 'Main Title'
        assert result['content'] == 'Content here'
        assert result['items'] == ['Item 1', 'Item 2']
    
    @pytest.mark.asyncio
    async def test_json_parsing(self, parser):
        """Test JSON content parsing."""
        json_str = '{"title": "Test", "nested": {"value": "data"}}'
        
        selectors = {
            'title': 'title',
            'nested_value': 'nested.value'
        }
        
        result = await parser.parse(json_str, 'json', selectors)
        
        assert result['title'] == 'Test'
        assert result['nested_value'] == 'data'
    
    @pytest.mark.asyncio
    async def test_missing_selectors(self, parser):
        """Test handling of missing selectors."""
        html = '<html><body><p>Simple content</p></body></html>'
        selectors = {'nonexistent': '.missing-class'}
        
        result = await parser.parse(html, 'html', selectors)
        
        assert result['nonexistent'] is None

class TestScrapingService:
    """Test main scraping service functionality."""
    
    @pytest.fixture
    def service(self):
        return ScrapingService()
    
    @pytest.mark.asyncio
    async def test_service_lifecycle(self, service):
        """Test service start and stop."""
        await service.start(num_workers=1)
        assert service._running
        assert len(service._workers) == 1
        
        await service.stop()
        assert not service._running
    
    @pytest.mark.asyncio
    async def test_scrape_url_success(self, service):
        """Test successful URL scraping."""
        # Mock HTTP response
        mock_content = "<html><title>Test</title></html>"
        
        with patch.object(service, '_fetch_content') as mock_fetch:
            mock_fetch.return_value = (mock_content, 'text/html')
            
            result = await service.scrape_url(
                "https://example.com",
                {'title': 'title'}
            )
            
            assert result.success
            assert result.data['title'] == 'Test'
            assert result.url == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_scrape_url_failure(self, service):
        """Test handling of scraping failures."""
        with patch.object(service, '_fetch_content') as mock_fetch:
            mock_fetch.side_effect = Exception("Network error")
            
            result = await service.scrape_url(
                "https://example.com",
                {'title': 'title'}
            )
            
            assert not result.success
            assert "Network error" in result.error
    
    @pytest.mark.asyncio
    async def test_get_stats(self, service):
        """Test statistics retrieval."""
        stats = service.get_stats()
        
        assert 'running' in stats
        assert 'workers' in stats
        assert 'queue_size' in stats
        assert 'domain_stats' in stats

class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @pytest.mark.asyncio
    async def test_scrape_url_function(self):
        """Test the scrape_url convenience function."""
        with patch('{{PROJECT_NAME}}.tasks.web_scraping.service.get_scraping_service') as mock_get_service:
            mock_service = AsyncMock()
            mock_result = ScrapingResult(
                url="https://example.com",
                success=True,
                data={'title': 'Test'},
                metadata={}
            )
            mock_service.scrape_url.return_value = mock_result
            mock_get_service.return_value = mock_service
            
            result = await scrape_url("https://example.com", {'title': 'title'})
            
            assert result.success
            mock_service.scrape_url.assert_called_once_with(
                "https://example.com", 
                {'title': 'title'}
            )

class TestIntegration:
    """Integration tests for the scraping system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_scraping(self):
        """Test complete scraping workflow."""
        service = ScrapingService()
        
        try:
            await service.start(num_workers=1)
            
            # Mock the HTTP request
            html_content = """
            <html>
                <head><title>Integration Test</title></head>
                <body>
                    <h1>Test Page</h1>
                    <p class="description">Test description</p>
                </body>
            </html>
            """
            
            with patch.object(service, '_fetch_content') as mock_fetch:
                mock_fetch.return_value = (html_content, 'text/html')
                
                result = await service.scrape_url(
                    "https://example.com",
                    {
                        'title': 'title',
                        'heading': 'h1',
                        'description': 'p.description'
                    }
                )
                
                assert result.success
                assert result.data['title'] == 'Integration Test'
                assert result.data['heading'] == 'Test Page'
                assert result.data['description'] == 'Test description'
                
        finally:
            await service.stop()
    
    @pytest.mark.asyncio
    async def test_multiple_urls_scraping(self):
        """Test scraping multiple URLs concurrently."""
        service = ScrapingService()
        
        try:
            await service.start(num_workers=2)
            
            urls = [
                {
                    'url': 'https://example.com/page1',
                    'selectors': {'title': 'title'}
                },
                {
                    'url': 'https://example.com/page2', 
                    'selectors': {'title': 'title'}
                }
            ]
            
            html_content = "<html><title>Page Title</title></html>"
            
            with patch.object(service, '_fetch_content') as mock_fetch:
                mock_fetch.return_value = (html_content, 'text/html')
                
                results = await service.scrape_urls(urls)
                
                assert len(results) == 2
                assert all(result.success for result in results)
                assert all(result.data['title'] == 'Page Title' for result in results)
                
        finally:
            await service.stop()

# Test configuration and fixtures
@pytest.fixture
def sample_html():
    """Sample HTML content for testing."""
    return """
    <html>
        <head>
            <title>Sample Page</title>
            <meta name="description" content="Sample description">
        </head>
        <body>
            <header>
                <h1 class="main-title">Main Header</h1>
            </header>
            <main>
                <article class="content">
                    <h2>Article Title</h2>
                    <p>Article content goes here.</p>
                </article>
                <aside class="sidebar">
                    <ul class="nav">
                        <li><a href="#home">Home</a></li>
                        <li><a href="#about">About</a></li>
                    </ul>
                </aside>
            </main>
        </body>
    </html>
    """

@pytest.fixture
def sample_json():
    """Sample JSON content for testing."""
    return {
        "title": "Sample JSON",
        "metadata": {
            "author": "Test Author",
            "created": "2024-01-01"
        },
        "content": {
            "sections": [
                {"title": "Section 1", "text": "Content 1"},
                {"title": "Section 2", "text": "Content 2"}
            ]
        }
    }

# Performance tests
class TestPerformance:
    """Performance and load tests."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test handling of concurrent requests."""
        service = ScrapingService()
        
        try:
            await service.start(num_workers=5)
            
            # Create many concurrent requests
            tasks = []
            for i in range(10):
                task = service.scrape_url(
                    f"https://example.com/page{i}",
                    {'title': 'title'}
                )
                tasks.append(task)
            
            # Mock responses
            with patch.object(service, '_fetch_content') as mock_fetch:
                mock_fetch.return_value = ("<html><title>Test</title></html>", 'text/html')
                
                results = await asyncio.gather(*tasks)
                
                assert len(results) == 10
                assert all(result.success for result in results)
                
        finally:
            await service.stop()

# Error handling tests
class TestErrorHandling:
    """Test error handling and recovery."""
    
    @pytest.mark.asyncio
    async def test_network_error_retry(self):
        """Test retry logic for network errors."""
        service = ScrapingService()
        
        # Configure to fail first time, succeed second time
        call_count = 0
        def mock_fetch(url):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Network error")
            return ("<html><title>Success</title></html>", 'text/html')
        
        with patch.object(service, '_fetch_content', side_effect=mock_fetch):
            result = await service.scrape_url(
                "https://example.com",
                {'title': 'title'},
                retry_attempts=2
            )
            
            assert result.success
            assert result.data['title'] == 'Success'
            assert call_count == 2  # Should have retried
    
    @pytest.mark.asyncio
    async def test_parsing_error_handling(self):
        """Test handling of parsing errors."""
        service = ScrapingService()
        
        with patch.object(service, '_fetch_content') as mock_fetch:
            # Return malformed HTML
            mock_fetch.return_value = ("<html><title>Test", 'text/html')
            
            result = await service.scrape_url(
                "https://example.com",
                {'title': 'title'}
            )
            
            # Should fail due to parsing error
            assert not result.success
            assert "parsing" in result.error.lower()

if __name__ == '__main__':
    pytest.main([__file__])
