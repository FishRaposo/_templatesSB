"""
Base Pipeline - Abstract base class for all pipelines
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Generic, Iterator, List, Optional, TypeVar

import logging
from contextlib import contextmanager

from ..utils.state import StateManager
from ..utils.metrics import MetricsCollector


logger = logging.getLogger(__name__)


# ============================================================================
# Type Variables
# ============================================================================

T = TypeVar("T")  # Input type
U = TypeVar("U")  # Output type


# ============================================================================
# Pipeline Status
# ============================================================================

class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"  # Some records failed


# ============================================================================
# Pipeline Result
# ============================================================================

@dataclass
class PipelineResult:
    """Result of a pipeline run."""
    
    status: PipelineStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    records_extracted: int = 0
    records_transformed: int = 0
    records_loaded: int = 0
    records_failed: int = 0
    
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> Optional[float]:
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def success_rate(self) -> float:
        total = self.records_extracted
        if total == 0:
            return 1.0
        return (total - self.records_failed) / total


# ============================================================================
# Base Extractor
# ============================================================================

class BaseExtractor(ABC, Generic[T]):
    """Base class for data extractors."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        state_manager: Optional[StateManager] = None,
    ):
        self.config = config
        self.state_manager = state_manager
        self._setup()
    
    def _setup(self):
        """Override for custom setup."""
        pass
    
    @abstractmethod
    def extract(self) -> Iterator[T]:
        """Extract data from source. Yields records."""
        pass
    
    def get_watermark(self, key: str) -> Optional[str]:
        """Get last processed watermark for incremental extraction."""
        if self.state_manager:
            return self.state_manager.get(key)
        return None
    
    def set_watermark(self, key: str, value: str):
        """Set watermark after successful extraction."""
        if self.state_manager:
            self.state_manager.set(key, value)
    
    def validate_connection(self) -> bool:
        """Validate connection to source."""
        return True


# ============================================================================
# Base Transformer
# ============================================================================

class BaseTransformer(ABC, Generic[T, U]):
    """Base class for data transformers."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._setup()
    
    def _setup(self):
        """Override for custom setup."""
        pass
    
    @abstractmethod
    def transform(self, record: T) -> Optional[U]:
        """
        Transform a single record.
        Return None to filter out the record.
        """
        pass
    
    def transform_batch(self, records: List[T]) -> List[U]:
        """Transform a batch of records."""
        results = []
        for record in records:
            try:
                transformed = self.transform(record)
                if transformed is not None:
                    results.append(transformed)
            except Exception as e:
                logger.warning(f"Transform error: {e}, skipping record")
        return results


# ============================================================================
# Base Loader
# ============================================================================

class LoadMode(str, Enum):
    INSERT = "insert"
    UPSERT = "upsert"
    REPLACE = "replace"
    APPEND = "append"


class BaseLoader(ABC, Generic[T]):
    """Base class for data loaders."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        mode: LoadMode = LoadMode.UPSERT,
        batch_size: int = 1000,
    ):
        self.config = config
        self.mode = mode
        self.batch_size = batch_size
        self._setup()
    
    def _setup(self):
        """Override for custom setup."""
        pass
    
    @abstractmethod
    def load(self, records: List[T]) -> int:
        """
        Load records to target.
        Returns number of records loaded.
        """
        pass
    
    def load_batch(self, records: Iterator[T]) -> int:
        """Load records in batches."""
        total_loaded = 0
        batch = []
        
        for record in records:
            batch.append(record)
            
            if len(batch) >= self.batch_size:
                loaded = self.load(batch)
                total_loaded += loaded
                batch = []
        
        # Load remaining records
        if batch:
            loaded = self.load(batch)
            total_loaded += loaded
        
        return total_loaded
    
    def validate_connection(self) -> bool:
        """Validate connection to target."""
        return True
    
    @contextmanager
    def transaction(self):
        """Context manager for transactional loads."""
        yield


# ============================================================================
# Base Pipeline
# ============================================================================

class BasePipeline(ABC):
    """Base class for ETL pipelines."""
    
    def __init__(
        self,
        name: str,
        config: Dict[str, Any],
        state_manager: Optional[StateManager] = None,
        metrics: Optional[MetricsCollector] = None,
    ):
        self.name = name
        self.config = config
        self.state_manager = state_manager or StateManager()
        self.metrics = metrics or MetricsCollector()
        
        self._result: Optional[PipelineResult] = None
        self._setup()
    
    def _setup(self):
        """Override for custom setup."""
        pass
    
    @abstractmethod
    def create_extractor(self) -> BaseExtractor:
        """Create the extractor for this pipeline."""
        pass
    
    @abstractmethod
    def create_transformers(self) -> List[BaseTransformer]:
        """Create the transformers for this pipeline."""
        pass
    
    @abstractmethod
    def create_loader(self) -> BaseLoader:
        """Create the loader for this pipeline."""
        pass
    
    def run(self) -> PipelineResult:
        """Execute the pipeline."""
        self._result = PipelineResult(
            status=PipelineStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        
        try:
            # Create components
            extractor = self.create_extractor()
            transformers = self.create_transformers()
            loader = self.create_loader()
            
            # Validate connections
            if not extractor.validate_connection():
                raise ConnectionError("Extractor connection failed")
            if not loader.validate_connection():
                raise ConnectionError("Loader connection failed")
            
            # Extract
            logger.info(f"Pipeline {self.name}: Starting extraction")
            records = list(extractor.extract())
            self._result.records_extracted = len(records)
            
            self.metrics.increment(f"{self.name}.extracted", len(records))
            logger.info(f"Pipeline {self.name}: Extracted {len(records)} records")
            
            # Transform
            logger.info(f"Pipeline {self.name}: Starting transformation")
            for transformer in transformers:
                records = transformer.transform_batch(records)
            
            self._result.records_transformed = len(records)
            self.metrics.increment(f"{self.name}.transformed", len(records))
            logger.info(f"Pipeline {self.name}: Transformed {len(records)} records")
            
            # Load
            logger.info(f"Pipeline {self.name}: Starting load")
            with loader.transaction():
                loaded = loader.load(records)
            
            self._result.records_loaded = loaded
            self.metrics.increment(f"{self.name}.loaded", loaded)
            logger.info(f"Pipeline {self.name}: Loaded {loaded} records")
            
            # Success
            self._result.status = PipelineStatus.SUCCESS
            self._result.completed_at = datetime.utcnow()
            
            self.metrics.timing(
                f"{self.name}.duration",
                self._result.duration_seconds or 0,
            )
            
        except Exception as e:
            logger.exception(f"Pipeline {self.name} failed: {e}")
            self._result.status = PipelineStatus.FAILED
            self._result.completed_at = datetime.utcnow()
            self._result.errors.append({
                "type": type(e).__name__,
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            })
            
            self.metrics.increment(f"{self.name}.errors")
        
        return self._result
    
    def run_incremental(self, watermark_key: str) -> PipelineResult:
        """Run pipeline with incremental extraction."""
        # Get last watermark
        last_watermark = self.state_manager.get(watermark_key)
        if last_watermark:
            self.config["incremental"] = {
                "from": last_watermark,
            }
        
        # Run pipeline
        result = self.run()
        
        # Update watermark on success
        if result.status == PipelineStatus.SUCCESS:
            new_watermark = datetime.utcnow().isoformat()
            self.state_manager.set(watermark_key, new_watermark)
        
        return result


# ============================================================================
# Pipeline Builder
# ============================================================================

class PipelineBuilder:
    """Fluent builder for pipelines."""
    
    def __init__(self, name: str):
        self._name = name
        self._config: Dict[str, Any] = {}
        self._extractor_factory = None
        self._transformer_factories = []
        self._loader_factory = None
    
    def with_config(self, config: Dict[str, Any]) -> "PipelineBuilder":
        self._config.update(config)
        return self
    
    def extract_from(self, factory) -> "PipelineBuilder":
        self._extractor_factory = factory
        return self
    
    def transform_with(self, factory) -> "PipelineBuilder":
        self._transformer_factories.append(factory)
        return self
    
    def load_to(self, factory) -> "PipelineBuilder":
        self._loader_factory = factory
        return self
    
    def build(self) -> BasePipeline:
        """Build the pipeline."""
        
        class DynamicPipeline(BasePipeline):
            def __init__(inner_self, extractor_factory, transformer_factories, loader_factory):
                super().__init__(self._name, self._config)
                inner_self._extractor_factory = extractor_factory
                inner_self._transformer_factories = transformer_factories
                inner_self._loader_factory = loader_factory
            
            def create_extractor(inner_self):
                return inner_self._extractor_factory(inner_self.config)
            
            def create_transformers(inner_self):
                return [f(inner_self.config) for f in inner_self._transformer_factories]
            
            def create_loader(inner_self):
                return inner_self._loader_factory(inner_self.config)
        
        return DynamicPipeline(
            self._extractor_factory,
            self._transformer_factories,
            self._loader_factory,
        )
