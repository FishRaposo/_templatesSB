"""
Data Extractors - API, Database, File
"""

from abc import ABC
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional
import json
import logging

import httpx

from .base import BaseExtractor


logger = logging.getLogger(__name__)


# ============================================================================
# API Extractor
# ============================================================================

class APIExtractor(BaseExtractor[Dict[str, Any]]):
    """Extract data from REST APIs."""
    
    def _setup(self):
        self.base_url = self.config["source"]
        self.auth_config = self.config.get("auth", {})
        self.pagination = self.config.get("pagination", {})
        self.incremental = self.config.get("incremental", {})
        
        # Setup HTTP client
        self._client = httpx.Client(
            timeout=self.config.get("timeout", 30),
            headers=self._build_headers(),
        )
    
    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including auth."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        auth_type = self.auth_config.get("type")
        
        if auth_type == "bearer":
            import os
            token = os.getenv(self.auth_config.get("token_env", "API_TOKEN"))
            if token:
                headers["Authorization"] = f"Bearer {token}"
        
        elif auth_type == "api_key":
            import os
            key = os.getenv(self.auth_config.get("key_env", "API_KEY"))
            header_name = self.auth_config.get("header", "X-API-Key")
            if key:
                headers[header_name] = key
        
        return headers
    
    def extract(self) -> Iterator[Dict[str, Any]]:
        """Extract data from API with pagination."""
        pagination_type = self.pagination.get("type", "none")
        
        if pagination_type == "offset":
            yield from self._extract_offset_pagination()
        elif pagination_type == "cursor":
            yield from self._extract_cursor_pagination()
        elif pagination_type == "page":
            yield from self._extract_page_pagination()
        else:
            yield from self._extract_single()
    
    def _extract_single(self) -> Iterator[Dict[str, Any]]:
        """Extract without pagination."""
        response = self._client.get(self.base_url, params=self._build_params())
        response.raise_for_status()
        
        data = response.json()
        data_path = self.config.get("data_path", "data")
        
        records = self._get_nested(data, data_path)
        for record in records:
            yield record
    
    def _extract_offset_pagination(self) -> Iterator[Dict[str, Any]]:
        """Extract with offset-based pagination."""
        page_size = self.pagination.get("page_size", 100)
        offset = 0
        
        while True:
            params = self._build_params()
            params["offset"] = offset
            params["limit"] = page_size
            
            response = self._client.get(self.base_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            data_path = self.config.get("data_path", "data")
            records = self._get_nested(data, data_path)
            
            if not records:
                break
            
            for record in records:
                yield record
            
            if len(records) < page_size:
                break
            
            offset += page_size
    
    def _extract_cursor_pagination(self) -> Iterator[Dict[str, Any]]:
        """Extract with cursor-based pagination."""
        page_size = self.pagination.get("page_size", 100)
        cursor = None
        cursor_param = self.pagination.get("cursor_param", "cursor")
        cursor_path = self.pagination.get("cursor_path", "next_cursor")
        
        while True:
            params = self._build_params()
            params["limit"] = page_size
            if cursor:
                params[cursor_param] = cursor
            
            response = self._client.get(self.base_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            data_path = self.config.get("data_path", "data")
            records = self._get_nested(data, data_path)
            
            for record in records:
                yield record
            
            # Get next cursor
            cursor = self._get_nested(data, cursor_path)
            if not cursor or not records:
                break
    
    def _extract_page_pagination(self) -> Iterator[Dict[str, Any]]:
        """Extract with page-based pagination."""
        page_size = self.pagination.get("page_size", 100)
        page = 1
        
        while True:
            params = self._build_params()
            params["page"] = page
            params["per_page"] = page_size
            
            response = self._client.get(self.base_url, params=params)
            response.raise_for_status()
            
            data = response.json()
            data_path = self.config.get("data_path", "data")
            records = self._get_nested(data, data_path)
            
            if not records:
                break
            
            for record in records:
                yield record
            
            if len(records) < page_size:
                break
            
            page += 1
    
    def _build_params(self) -> Dict[str, Any]:
        """Build query parameters including incremental filters."""
        params = dict(self.config.get("params", {}))
        
        # Add incremental filter
        if self.incremental:
            watermark_key = self.incremental.get("watermark_key")
            field = self.incremental.get("field", "updated_at")
            
            if watermark_key:
                last_value = self.get_watermark(watermark_key)
                if last_value:
                    params[f"{field}_gte"] = last_value
        
        return params
    
    def _get_nested(self, data: Dict, path: str) -> Any:
        """Get nested value from dict using dot notation."""
        if not path:
            return data
        
        parts = path.split(".")
        for part in parts:
            if isinstance(data, dict):
                data = data.get(part)
            else:
                return None
        return data
    
    def validate_connection(self) -> bool:
        """Validate API connection."""
        try:
            response = self._client.head(self.base_url)
            return response.status_code < 500
        except Exception as e:
            logger.error(f"API connection failed: {e}")
            return False


# ============================================================================
# Database Extractor
# ============================================================================

class DatabaseExtractor(BaseExtractor[Dict[str, Any]]):
    """Extract data from databases."""
    
    def _setup(self):
        self.connection_string = self.config["connection_string"]
        self.query = self.config.get("query")
        self.table = self.config.get("table")
        self.incremental = self.config.get("incremental", {})
        self.batch_size = self.config.get("batch_size", 10000)
        
        # Import database library
        from sqlalchemy import create_engine
        self._engine = create_engine(self.connection_string)
    
    def extract(self) -> Iterator[Dict[str, Any]]:
        """Extract data from database."""
        query = self._build_query()
        
        from sqlalchemy import text
        
        with self._engine.connect() as conn:
            result = conn.execute(text(query))
            columns = result.keys()
            
            batch = []
            for row in result:
                record = dict(zip(columns, row))
                batch.append(record)
                
                if len(batch) >= self.batch_size:
                    yield from batch
                    batch = []
            
            if batch:
                yield from batch
    
    def _build_query(self) -> str:
        """Build SQL query with incremental filters."""
        if self.query:
            base_query = self.query
        else:
            base_query = f"SELECT * FROM {self.table}"
        
        # Add incremental filter
        conditions = []
        if self.incremental:
            watermark_key = self.incremental.get("watermark_key")
            field = self.incremental.get("field", "updated_at")
            
            if watermark_key:
                last_value = self.get_watermark(watermark_key)
                if last_value:
                    conditions.append(f"{field} > '{last_value}'")
        
        if conditions:
            if "WHERE" in base_query.upper():
                base_query += " AND " + " AND ".join(conditions)
            else:
                base_query += " WHERE " + " AND ".join(conditions)
        
        return base_query
    
    def validate_connection(self) -> bool:
        """Validate database connection."""
        try:
            with self._engine.connect() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False


# ============================================================================
# File Extractor
# ============================================================================

class FileExtractor(BaseExtractor[Dict[str, Any]]):
    """Extract data from files (local, S3, GCS)."""
    
    def _setup(self):
        self.source_path = self.config["source"]
        self.file_format = self.config.get("format", "json")
        self.compression = self.config.get("compression")
    
    def extract(self) -> Iterator[Dict[str, Any]]:
        """Extract data from file(s)."""
        if self.source_path.startswith("s3://"):
            yield from self._extract_s3()
        elif self.source_path.startswith("gs://"):
            yield from self._extract_gcs()
        else:
            yield from self._extract_local()
    
    def _extract_local(self) -> Iterator[Dict[str, Any]]:
        """Extract from local file system."""
        import glob
        from pathlib import Path
        
        for file_path in glob.glob(self.source_path):
            logger.info(f"Extracting from {file_path}")
            yield from self._read_file(Path(file_path))
    
    def _extract_s3(self) -> Iterator[Dict[str, Any]]:
        """Extract from S3."""
        import boto3
        from urllib.parse import urlparse
        
        parsed = urlparse(self.source_path)
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/")
        
        s3 = boto3.client("s3")
        
        # List objects
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                logger.info(f"Extracting from s3://{bucket}/{key}")
                
                # Download and read
                response = s3.get_object(Bucket=bucket, Key=key)
                body = response["Body"].read()
                
                yield from self._parse_content(body)
    
    def _extract_gcs(self) -> Iterator[Dict[str, Any]]:
        """Extract from Google Cloud Storage."""
        from google.cloud import storage
        from urllib.parse import urlparse
        
        parsed = urlparse(self.source_path)
        bucket_name = parsed.netloc
        prefix = parsed.path.lstrip("/")
        
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        
        for blob in bucket.list_blobs(prefix=prefix):
            logger.info(f"Extracting from gs://{bucket_name}/{blob.name}")
            content = blob.download_as_bytes()
            yield from self._parse_content(content)
    
    def _read_file(self, path) -> Iterator[Dict[str, Any]]:
        """Read file from path."""
        open_func = open
        
        if self.compression == "gzip" or str(path).endswith(".gz"):
            import gzip
            open_func = gzip.open
        
        with open_func(path, "rb") as f:
            content = f.read()
            yield from self._parse_content(content)
    
    def _parse_content(self, content: bytes) -> Iterator[Dict[str, Any]]:
        """Parse file content based on format."""
        if self.file_format == "json":
            data = json.loads(content)
            if isinstance(data, list):
                yield from data
            else:
                yield data
        
        elif self.file_format == "jsonl":
            for line in content.decode().split("\n"):
                if line.strip():
                    yield json.loads(line)
        
        elif self.file_format == "csv":
            import csv
            import io
            reader = csv.DictReader(io.StringIO(content.decode()))
            yield from reader
        
        elif self.file_format == "parquet":
            import pyarrow.parquet as pq
            import io
            table = pq.read_table(io.BytesIO(content))
            yield from table.to_pylist()
        
        else:
            raise ValueError(f"Unsupported format: {self.file_format}")


# ============================================================================
# Extractor Registry
# ============================================================================

EXTRACTORS = {
    "api": APIExtractor,
    "database": DatabaseExtractor,
    "file": FileExtractor,
}


def create_extractor(config: Dict[str, Any]) -> BaseExtractor:
    """Create extractor from config."""
    extractor_type = config.get("type", "api")
    
    if extractor_type not in EXTRACTORS:
        raise ValueError(f"Unknown extractor type: {extractor_type}")
    
    return EXTRACTORS[extractor_type](config)
