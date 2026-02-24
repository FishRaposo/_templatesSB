"""
Data Transformers - Cleaning, Validation, Enrichment
"""

from abc import ABC
from datetime import datetime, date
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Type, Union
import re
import logging

from pydantic import BaseModel, ValidationError

from .base import BaseTransformer


logger = logging.getLogger(__name__)


# ============================================================================
# Cleaning Transformer
# ============================================================================

class CleaningTransformer(BaseTransformer[Dict[str, Any], Dict[str, Any]]):
    """Clean and normalize data."""
    
    def _setup(self):
        self.operations = self.config.get("operations", [])
        
        # Map operation names to methods
        self._operation_map = {
            "trim_strings": self._trim_strings,
            "normalize_emails": self._normalize_emails,
            "normalize_phones": self._normalize_phones,
            "remove_nulls": self._remove_nulls,
            "lowercase_keys": self._lowercase_keys,
            "snake_case_keys": self._snake_case_keys,
            "parse_dates": self._parse_dates,
            "remove_html": self._remove_html,
        }
    
    def transform(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Apply cleaning operations to record."""
        result = dict(record)
        
        for operation in self.operations:
            if isinstance(operation, str):
                op_name = operation
                op_config = {}
            else:
                op_name = operation.get("name")
                op_config = operation.get("config", {})
            
            if op_name in self._operation_map:
                result = self._operation_map[op_name](result, op_config)
        
        return result
    
    def _trim_strings(self, record: Dict, config: Dict) -> Dict:
        """Trim whitespace from string values."""
        return {
            k: v.strip() if isinstance(v, str) else v
            for k, v in record.items()
        }
    
    def _normalize_emails(self, record: Dict, config: Dict) -> Dict:
        """Normalize email addresses."""
        fields = config.get("fields", ["email"])
        
        for field in fields:
            if field in record and isinstance(record[field], str):
                email = record[field].lower().strip()
                # Remove dots from gmail usernames
                if "@gmail.com" in email:
                    parts = email.split("@")
                    email = parts[0].replace(".", "") + "@" + parts[1]
                record[field] = email
        
        return record
    
    def _normalize_phones(self, record: Dict, config: Dict) -> Dict:
        """Normalize phone numbers to E.164 format."""
        fields = config.get("fields", ["phone"])
        default_country = config.get("default_country", "US")
        
        for field in fields:
            if field in record and record[field]:
                # Remove non-digits
                phone = re.sub(r'\D', '', str(record[field]))
                
                # Add country code if missing
                if len(phone) == 10 and default_country == "US":
                    phone = "1" + phone
                
                record[field] = f"+{phone}" if phone else None
        
        return record
    
    def _remove_nulls(self, record: Dict, config: Dict) -> Dict:
        """Remove null/empty values."""
        null_values = config.get("null_values", [None, "", "null", "NULL", "None"])
        
        return {
            k: v for k, v in record.items()
            if v not in null_values
        }
    
    def _lowercase_keys(self, record: Dict, config: Dict) -> Dict:
        """Convert keys to lowercase."""
        return {k.lower(): v for k, v in record.items()}
    
    def _snake_case_keys(self, record: Dict, config: Dict) -> Dict:
        """Convert keys to snake_case."""
        def to_snake(s: str) -> str:
            s = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
            return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s).lower()
        
        return {to_snake(k): v for k, v in record.items()}
    
    def _parse_dates(self, record: Dict, config: Dict) -> Dict:
        """Parse date strings to datetime objects."""
        fields = config.get("fields", [])
        formats = config.get("formats", [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%d/%m/%Y",
            "%m/%d/%Y",
        ])
        
        for field in fields:
            if field in record and isinstance(record[field], str):
                value = record[field]
                for fmt in formats:
                    try:
                        record[field] = datetime.strptime(value, fmt)
                        break
                    except ValueError:
                        continue
        
        return record
    
    def _remove_html(self, record: Dict, config: Dict) -> Dict:
        """Remove HTML tags from string fields."""
        fields = config.get("fields", [])
        pattern = re.compile('<.*?>')
        
        for field in fields:
            if field in record and isinstance(record[field], str):
                record[field] = pattern.sub('', record[field])
        
        return record


# ============================================================================
# Validation Transformer
# ============================================================================

class ValidationTransformer(BaseTransformer[Dict[str, Any], Dict[str, Any]]):
    """Validate records against a schema."""
    
    def _setup(self):
        schema_name = self.config.get("schema")
        self.on_error = self.config.get("on_error", "skip")  # skip, raise, log
        
        # Get schema class
        from ..models import schemas
        self.schema_class: Type[BaseModel] = getattr(schemas, schema_name, None)
        
        if not self.schema_class:
            raise ValueError(f"Schema not found: {schema_name}")
    
    def transform(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate record against schema."""
        try:
            validated = self.schema_class.model_validate(record)
            return validated.model_dump()
        
        except ValidationError as e:
            if self.on_error == "raise":
                raise
            elif self.on_error == "log":
                logger.warning(f"Validation error: {e}")
                return record
            else:  # skip
                logger.debug(f"Skipping invalid record: {e}")
                return None


# ============================================================================
# Enrichment Transformer
# ============================================================================

class EnrichmentTransformer(BaseTransformer[Dict[str, Any], Dict[str, Any]]):
    """Enrich records with additional data."""
    
    def _setup(self):
        self.lookups = self.config.get("lookups", [])
        self._lookup_caches: Dict[str, Dict] = {}
        
        # Pre-load lookup tables
        for lookup in self.lookups:
            self._load_lookup(lookup)
    
    def _load_lookup(self, lookup: Dict):
        """Load lookup table into cache."""
        table = lookup.get("table")
        source = lookup.get("source", "database")
        
        if source == "database":
            # Load from database
            from sqlalchemy import create_engine, text
            import os
            
            engine = create_engine(os.getenv("DATABASE_URL", ""))
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT * FROM {table}"))
                key_field = lookup.get("on")
                
                self._lookup_caches[table] = {
                    row[key_field]: dict(row._mapping)
                    for row in result
                }
        
        elif source == "file":
            import json
            with open(lookup.get("path")) as f:
                data = json.load(f)
                key_field = lookup.get("on")
                self._lookup_caches[table] = {
                    item[key_field]: item
                    for item in data
                }
    
    def transform(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich record with lookup data."""
        result = dict(record)
        
        for lookup in self.lookups:
            table = lookup.get("table")
            on_field = lookup.get("on")
            fields = lookup.get("fields", [])
            
            lookup_key = record.get(on_field)
            if lookup_key and table in self._lookup_caches:
                lookup_data = self._lookup_caches[table].get(lookup_key, {})
                
                for field in fields:
                    if field in lookup_data:
                        result[field] = lookup_data[field]
        
        return result


# ============================================================================
# Aggregation Transformer
# ============================================================================

class AggregationTransformer(BaseTransformer[List[Dict], Dict[str, Any]]):
    """Aggregate records into summary."""
    
    def _setup(self):
        self.group_by = self.config.get("group_by", [])
        self.aggregations = self.config.get("aggregations", {})
    
    def transform(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Pass through - aggregation happens in transform_batch."""
        return record
    
    def transform_batch(self, records: List[Dict]) -> List[Dict]:
        """Aggregate batch of records."""
        if not self.group_by:
            # Single aggregation
            return [self._aggregate(records)]
        
        # Group records
        groups: Dict[tuple, List[Dict]] = {}
        for record in records:
            key = tuple(record.get(f) for f in self.group_by)
            if key not in groups:
                groups[key] = []
            groups[key].append(record)
        
        # Aggregate each group
        results = []
        for key, group in groups.items():
            result = dict(zip(self.group_by, key))
            result.update(self._aggregate(group))
            results.append(result)
        
        return results
    
    def _aggregate(self, records: List[Dict]) -> Dict:
        """Apply aggregation functions."""
        result = {}
        
        for output_name, agg_config in self.aggregations.items():
            field = agg_config.get("field")
            func = agg_config.get("func")
            
            values = [r.get(field) for r in records if r.get(field) is not None]
            
            if func == "sum":
                result[output_name] = sum(values)
            elif func == "count":
                result[output_name] = len(values)
            elif func == "avg":
                result[output_name] = sum(values) / len(values) if values else 0
            elif func == "min":
                result[output_name] = min(values) if values else None
            elif func == "max":
                result[output_name] = max(values) if values else None
            elif func == "first":
                result[output_name] = values[0] if values else None
            elif func == "last":
                result[output_name] = values[-1] if values else None
        
        return result


# ============================================================================
# Deduplication Transformer
# ============================================================================

class DeduplicationTransformer(BaseTransformer[Dict[str, Any], Dict[str, Any]]):
    """Remove duplicate records."""
    
    def _setup(self):
        self.key_fields = self.config.get("key", [])
        self.strategy = self.config.get("strategy", "first")  # first, last
        self._seen: Dict[tuple, Dict] = {}
    
    def transform(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Track record for deduplication."""
        key = tuple(record.get(f) for f in self.key_fields)
        
        if key in self._seen:
            if self.strategy == "last":
                self._seen[key] = record
            return None
        
        self._seen[key] = record
        return record
    
    def transform_batch(self, records: List[Dict]) -> List[Dict]:
        """Deduplicate batch."""
        self._seen = {}
        
        for record in records:
            self.transform(record)
        
        return list(self._seen.values())


# ============================================================================
# Transformer Registry
# ============================================================================

TRANSFORMERS = {
    "clean": CleaningTransformer,
    "validate": ValidationTransformer,
    "enrich": EnrichmentTransformer,
    "aggregate": AggregationTransformer,
    "deduplicate": DeduplicationTransformer,
}


def create_transformer(config: Dict[str, Any]) -> BaseTransformer:
    """Create transformer from config."""
    transformer_type = config.get("type", "clean")
    
    if transformer_type not in TRANSFORMERS:
        raise ValueError(f"Unknown transformer type: {transformer_type}")
    
    return TRANSFORMERS[transformer_type](config)
