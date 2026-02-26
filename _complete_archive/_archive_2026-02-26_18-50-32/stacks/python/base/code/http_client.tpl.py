"""
File: http_client.tpl.py
Purpose: Resilient HTTP client with retry logic
Generated for: {{PROJECT_NAME}}
"""

import asyncio
from typing import Any, Dict, Optional
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
import logging

logger = logging.getLogger(__name__)


class HTTPClientConfig:
    def __init__(
        self,
        base_url: str = "",
        timeout: float = 30.0,
        max_retries: int = 3,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = headers or {}


class HTTPClient:
    """Resilient async HTTP client with retry logic"""

    def __init__(self, config: HTTPClientConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            headers=self.config.headers,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if not self._client:
            raise RuntimeError("Client not initialized. Use async with context.")
        return self._client

    def _create_retry_decorator(self):
        return retry(
            stop=stop_after_attempt(self.config.max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
            before_sleep=lambda retry_state: logger.warning(
                f"Retry {retry_state.attempt_number} after {retry_state.outcome.exception()}"
            ),
        )

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make a GET request with retry logic"""
        @self._create_retry_decorator()
        async def _get():
            response = await self.client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response
        return await _get()

    async def post(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make a POST request with retry logic"""
        @self._create_retry_decorator()
        async def _post():
            response = await self.client.post(
                url, json=json, data=data, headers=headers
            )
            response.raise_for_status()
            return response
        return await _post()

    async def put(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make a PUT request with retry logic"""
        @self._create_retry_decorator()
        async def _put():
            response = await self.client.put(url, json=json, headers=headers)
            response.raise_for_status()
            return response
        return await _put()

    async def delete(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Make a DELETE request with retry logic"""
        @self._create_retry_decorator()
        async def _delete():
            response = await self.client.delete(url, headers=headers)
            response.raise_for_status()
            return response
        return await _delete()


# Usage:
# config = HTTPClientConfig(base_url="https://api.example.com", timeout=10.0)
# async with HTTPClient(config) as client:
#     response = await client.get("/users/1")
#     user = response.json()
