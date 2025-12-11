<!--
File: DATA-PROCESSING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Python Data Processing Patterns

## Purpose
Comprehensive guide to data processing patterns in Python, including ETL operations, data transformation, and analysis workflows.

## Core Data Processing Patterns

### 1. Basic Data Transformation
```python
import pandas as pd
import numpy as np
from typing import List, Dict, Any

def basic_data_transform(df: pd.DataFrame) -> pd.DataFrame:
    """Basic data transformation with pandas"""
    # Remove duplicates
    df = df.drop_duplicates()
    
    # Handle missing values
    df = df.fillna({'age': df['age'].median(), 'salary': df['salary'].mean()})
    
    # Convert data types
    df['date'] = pd.to_datetime(df['date'])
    df['category'] = df['category'].astype('category')
    
    # Create new features
    df['age_group'] = pd.cut(df['age'], bins=[0, 18, 35, 50, 100], labels=['Young', 'Adult', 'Middle', 'Senior'])
    df['salary_per_year'] = df['salary'] / (2024 - df['hire_year'])
    
    return df

def filter_and_aggregate(df: pd.DataFrame) -> pd.DataFrame:
    """Filter data and perform aggregations"""
    # Filter active employees
    active_df = df[df['status'] == 'active']
    
    # Group by department and calculate statistics
    dept_stats = active_df.groupby('department').agg({
        'salary': ['mean', 'median', 'std'],
        'age': 'mean',
        'employee_id': 'count'
    }).round(2)
    
    # Flatten column names
    dept_stats.columns = ['avg_salary', 'median_salary', 'salary_std', 'avg_age', 'employee_count']
    
    return dept_stats.reset_index()
```

### 2. ETL Pipeline Pattern
```python
import pandas as pd
import sqlalchemy as sa
from abc import ABC, abstractmethod
from typing import Any, Dict
import logging

class Extractor(ABC):
    """Abstract base class for data extractors"""
    
    @abstractmethod
    def extract(self) -> pd.DataFrame:
        pass

class Transformer(ABC):
    """Abstract base class for data transformers"""
    
    @abstractmethod
    def transform(self, data: pd.DataFrame) -> pd.DataFrame:
        pass

class Loader(ABC):
    """Abstract base class for data loaders"""
    
    @abstractmethod
    def load(self, data: pd.DataFrame) -> bool:
        pass

class CSVExtractor(Extractor):
    """Extract data from CSV files"""
    
    def __init__(self, file_path: str, **kwargs):
        self.file_path = file_path
        self.kwargs = kwargs
    
    def extract(self) -> pd.DataFrame:
        try:
            return pd.read_csv(self.file_path, **self.kwargs)
        except Exception as e:
            logging.error(f"Failed to extract from {self.file_path}: {e}")
            raise

class DatabaseExtractor(Extractor):
    """Extract data from database"""
    
    def __init__(self, connection_string: str, query: str):
        self.connection_string = connection_string
        self.query = query
    
    def extract(self) -> pd.DataFrame:
        try:
            engine = sa.create_engine(self.connection_string)
            return pd.read_sql(self.query, engine)
        except Exception as e:
            logging.error(f"Failed to extract from database: {e}")
            raise

class DataCleaner(Transformer):
    """Clean and transform raw data"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
    
    def transform(self, data: pd.DataFrame) -> pd.DataFrame:
        # Remove duplicates
        if self.config.get('remove_duplicates', True):
            data = data.drop_duplicates()
        
        # Handle missing values
        if 'fill_na' in self.config:
            data = data.fillna(self.config['fill_na'])
        
        # Convert data types
        if 'dtypes' in self.config:
            for col, dtype in self.config['dtypes'].items():
                data[col] = data[col].astype(dtype)
        
        return data

class DatabaseLoader(Loader):
    """Load data into database"""
    
    def __init__(self, connection_string: str, table_name: str, if_exists: str = 'append'):
        self.connection_string = connection_string
        self.table_name = table_name
        self.if_exists = if_exists
    
    def load(self, data: pd.DataFrame) -> bool:
        try:
            engine = sa.create_engine(self.connection_string)
            data.to_sql(self.table_name, engine, if_exists=self.if_exists, index=False)
            return True
        except Exception as e:
            logging.error(f"Failed to load to {self.table_name}: {e}")
            return False

class ETLPipeline:
    """ETL Pipeline orchestrator"""
    
    def __init__(self, extractor: Extractor, transformer: Transformer, loader: Loader):
        self.extractor = extractor
        self.transformer = transformer
        self.loader = loader
    
    def run(self) -> bool:
        """Run the complete ETL pipeline"""
        try:
            # Extract
            logging.info("Starting data extraction...")
            raw_data = self.extractor.extract()
            logging.info(f"Extracted {len(raw_data)} records")
            
            # Transform
            logging.info("Starting data transformation...")
            transformed_data = self.transformer.transform(raw_data)
            logging.info(f"Transformed {len(transformed_data)} records")
            
            # Load
            logging.info("Starting data loading...")
            success = self.loader.load(transformed_data)
            
            if success:
                logging.info("ETL pipeline completed successfully")
            else:
                logging.error("ETL pipeline failed during loading")
            
            return success
            
        except Exception as e:
            logging.error(f"ETL pipeline failed: {e}")
            return False

# Usage example
def create_etl_pipeline() -> ETLPipeline:
    """Create and configure ETL pipeline"""
    
    # Configure components
    extractor = CSVExtractor('data/raw_employees.csv')
    
    transformer = DataCleaner({
        'remove_duplicates': True,
        'fill_na': {'age': 0, 'salary': 0},
        'dtypes': {'hire_date': 'datetime64[ns]'}
    })
    
    loader = DatabaseLoader(
        'postgresql://user:pass@localhost/db',
        'employees',
        if_exists='replace'
    )
    
    return ETLPipeline(extractor, transformer, loader)
```

### 3. Data Validation Pattern
```python
import pandas as pd
from typing import List, Dict, Callable, Any
from dataclasses import dataclass
from enum import Enum

class ValidationLevel(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationResult:
    level: ValidationLevel
    message: str
    column: str = None
    row_index: int = None

class DataValidator:
    """Data validation framework"""
    
    def __init__(self):
        self.validators: List[Callable] = []
        self.results: List[ValidationResult] = []
    
    def add_validator(self, validator_func: Callable) -> 'DataValidator':
        """Add a validation function"""
        self.validators.append(validator_func)
        return self
    
    def validate(self, data: pd.DataFrame) -> List[ValidationResult]:
        """Run all validations on the data"""
        self.results = []
        
        for validator in self.validators:
            try:
                validator_results = validator(data)
                if isinstance(validator_results, list):
                    self.results.extend(validator_results)
                else:
                    self.results.append(validator_results)
            except Exception as e:
                self.results.append(ValidationResult(
                    ValidationLevel.ERROR,
                    f"Validator failed: {str(e)}"
                ))
        
        return self.results
    
    def get_errors(self) -> List[ValidationResult]:
        """Get only error-level results"""
        return [r for r in self.results if r.level == ValidationLevel.ERROR]
    
    def get_warnings(self) -> List[ValidationResult]:
        """Get only warning-level results"""
        return [r for r in self.results if r.level == ValidationLevel.WARNING]

# Common validation functions
def validate_not_null(column: str) -> Callable:
    """Create validator for non-null values"""
    def validator(data: pd.DataFrame) -> List[ValidationResult]:
        results = []
        null_mask = data[column].isnull()
        for idx in data[null_mask].index:
            results.append(ValidationResult(
                ValidationLevel.ERROR,
                f"Null value found in {column}",
                column=column,
                row_index=idx
            ))
        return results
    return validator

def validate_range(column: str, min_val: Any, max_val: Any) -> Callable:
    """Create validator for value ranges"""
    def validator(data: pd.DataFrame) -> List[ValidationResult]:
        results = []
        invalid_mask = (data[column] < min_val) | (data[column] > max_val)
        for idx in data[invalid_mask].index:
            results.append(ValidationResult(
                ValidationLevel.ERROR,
                f"Value {data[column][idx]} not in range [{min_val}, {max_val}]",
                column=column,
                row_index=idx
            ))
        return results
    return validator

def validate_email_format(column: str) -> Callable:
    """Create validator for email format"""
    import re
    
    def validator(data: pd.DataFrame) -> List[ValidationResult]:
        results = []
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        for idx, email in data[column].items():
            if pd.notna(email) and not re.match(email_pattern, str(email)):
                results.append(ValidationResult(
                    ValidationLevel.ERROR,
                    f"Invalid email format: {email}",
                    column=column,
                    row_index=idx
                ))
        return results
    return validator

# Usage example
def validate_employee_data(data: pd.DataFrame) -> List[ValidationResult]:
    """Validate employee data with multiple rules"""
    
    validator = DataValidator()
    validator.add_validator(validate_not_null('employee_id'))
    validator.add_validator(validate_not_null('email'))
    validator.add_validator(validate_range('age', 18, 100))
    validator.add_validator(validate_email_format('email'))
    
    return validator.validate(data)
```

## Advanced Data Processing

### 1. Streaming Data Processing
```python
import asyncio
import aiofiles
import json
from typing import AsyncIterator, Dict, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class DataEvent:
    timestamp: datetime
    data: Dict[str, Any]
    source: str

class StreamProcessor:
    """Async stream data processor"""
    
    def __init__(self):
        self.buffer = []
        self.buffer_size = 1000
        self.processors = []
    
    def add_processor(self, processor_func: Callable) -> 'StreamProcessor':
        """Add data processor function"""
        self.processors.append(processor_func)
        return self
    
    async def process_stream(self, stream: AsyncIterator[DataEvent]) -> AsyncIterator[Dict[str, Any]]:
        """Process data stream"""
        async for event in stream:
            # Apply all processors
            processed_data = event.data
            
            for processor in self.processors:
                processed_data = await processor(processed_data)
            
            yield processed_data

async def read_json_stream(file_path: str) -> AsyncIterator[DataEvent]:
    """Read JSON lines file as stream"""
    async with aiofiles.open(file_path, 'r') as file:
        async for line in file:
            if line.strip():
                data = json.loads(line)
                yield DataEvent(
                    timestamp=datetime.now(),
                    data=data,
                    source=file_path
                )

async def write_json_stream(file_path: str, stream: AsyncIterator[Dict[str, Any]]) -> None:
    """Write processed data to JSON lines file"""
    async with aiofiles.open(file_path, 'w') as file:
        async for data in stream:
            await file.write(json.dumps(data) + '\n')

# Example processors
async def enrich_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich data with additional information"""
    data['processed_at'] = datetime.now().isoformat()
    data['data_quality_score'] = calculate_quality_score(data)
    return data

async def filter_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter out invalid data"""
    if data.get('status') == 'invalid':
        return None
    return data

async def aggregate_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate data metrics"""
    data['metrics'] = {
        'field_count': len([k for k, v in data.items() if v is not None]),
        'has_required_fields': all(field in data for field in ['id', 'name'])
    }
    return data

# Usage example
async def process_data_streams():
    """Process multiple data streams"""
    
    # Create processor
    processor = StreamProcessor()
    processor.add_processor(enrich_data)
    processor.add_processor(filter_data)
    processor.add_processor(aggregate_data)
    
    # Process input stream
    input_stream = read_json_stream('data/input.jsonl')
    processed_stream = processor.process_stream(input_stream)
    
    # Write output stream
    await write_json_stream('data/output.jsonl', processed_stream)
```

### 2. Parallel Data Processing
```python
import multiprocessing as mp
import pandas as pd
from typing import List, Callable, Any
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import numpy as np

class ParallelProcessor:
    """Parallel data processing framework"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or mp.cpu_count()
    
    def process_chunks(self, 
                      data: pd.DataFrame, 
                      processor_func: Callable,
                      chunk_size: int = 1000) -> pd.DataFrame:
        """Process data in parallel chunks"""
        
        # Split data into chunks
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        
        # Process chunks in parallel
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            processed_chunks = list(executor.map(processor_func, chunks))
        
        # Combine results
        return pd.concat(processed_chunks, ignore_index=True)
    
    def process_with_threadpool(self,
                               data_list: List[Any],
                               processor_func: Callable) -> List[Any]:
        """Process list of items with thread pool"""
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = list(executor.map(processor_func, data_list))
        
        return results

def process_dataframe_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """Process a single chunk of data"""
    # Example: Calculate complex metrics
    chunk['complex_metric'] = chunk.apply(calculate_complex_metric, axis=1)
    chunk['normalized_value'] = (chunk['value'] - chunk['value'].mean()) / chunk['value'].std()
    return chunk

def calculate_complex_metric(row: pd.Series) -> float:
    """Calculate complex metric for a row"""
    # Simulate complex calculation
    return np.sqrt(row['value1']**2 + row['value2']**2) * row['weight']

# Usage example
def parallel_data_processing():
    """Example of parallel data processing"""
    
    # Generate sample data
    data = pd.DataFrame({
        'value1': np.random.randn(100000),
        'value2': np.random.randn(100000),
        'weight': np.random.uniform(0.1, 2.0, 100000)
    })
    
    # Process in parallel
    processor = ParallelProcessor()
    processed_data = processor.process_chunks(data, process_dataframe_chunk, chunk_size=10000)
    
    print(f"Processed {len(processed_data)} records in parallel")
    return processed_data
```

### 3. Memory-Efficient Processing
```python
import pandas as pd
import numpy as np
from typing import Iterator, Dict, Any
import gc
import psutil

class MemoryEfficientProcessor:
    """Memory-efficient data processing for large datasets"""
    
    def __init__(self, chunk_size: int = 10000):
        self.chunk_size = chunk_size
    
    def process_large_csv(self, 
                         file_path: str, 
                         processor_func: Callable,
                         output_path: str = None) -> pd.DataFrame:
        """Process large CSV file in chunks"""
        
        results = []
        
        # Read and process file in chunks
        for chunk in pd.read_csv(file_path, chunksize=self.chunk_size):
            # Process chunk
            processed_chunk = processor_func(chunk)
            results.append(processed_chunk)
            
            # Memory cleanup
            del chunk
            gc.collect()
            
            # Monitor memory usage
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 80:
                print(f"Warning: High memory usage: {memory_percent}%")
        
        # Combine results
        final_result = pd.concat(results, ignore_index=True)
        
        # Save to file if specified
        if output_path:
            final_result.to_csv(output_path, index=False)
        
        return final_result
    
    def process_with_generator(self,
                              data_generator: Iterator[pd.DataFrame],
                              processor_func: Callable) -> Iterator[pd.DataFrame]:
        """Process data using generator for memory efficiency"""
        
        for chunk in data_generator:
            processed_chunk = processor_func(chunk)
            yield processed_chunk
            
            # Memory cleanup
            del chunk
            gc.collect()

def memory_efficient_transform(chunk: pd.DataFrame) -> pd.DataFrame:
    """Memory-efficient data transformation"""
    
    # Use categorical data types to save memory
    for col in chunk.select_dtypes(include=['object']).columns:
        if chunk[col].nunique() < len(chunk) * 0.5:  # If cardinality is low
            chunk[col] = chunk[col].astype('category')
    
    # Downcast numeric types
    for col in chunk.select_dtypes(include=['int64']).columns:
        chunk[col] = pd.to_numeric(chunk[col], downcast='integer')
    
    for col in chunk.select_dtypes(include=['float64']).columns:
        chunk[col] = pd.to_numeric(chunk[col], downcast='float')
    
    return chunk

# Usage example
def process_large_dataset():
    """Process large dataset efficiently"""
    
    processor = MemoryEfficientProcessor(chunk_size=5000)
    
    # Process large CSV file
    result = processor.process_large_csv(
        'data/large_dataset.csv',
        memory_efficient_transform,
        'data/processed_dataset.csv'
    )
    
    return result
```

## Data Quality and Monitoring

### 1. Data Quality Metrics
```python
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class QualityDimension(Enum):
    COMPLETENESS = "completeness"
    ACCURACY = "accuracy"
    CONSISTENCY = "consistency"
    VALIDITY = "validity"
    UNIQUENESS = "uniqueness"

@dataclass
class QualityMetric:
    dimension: QualityDimension
    column: str
    score: float
    description: str

class DataQualityAssessor:
    """Assess data quality across multiple dimensions"""
    
    def assess_completeness(self, data: pd.DataFrame) -> List[QualityMetric]:
        """Assess data completeness"""
        metrics = []
        
        for column in data.columns:
            completeness = (data[column].notna().sum() / len(data)) * 100
            metrics.append(QualityMetric(
                QualityDimension.COMPLETENESS,
                column,
                completeness,
                f"{completeness:.1f}% of values are present"
            ))
        
        return metrics
    
    def assess_uniqueness(self, data: pd.DataFrame, key_columns: List[str]) -> List[QualityMetric]:
        """Assess data uniqueness"""
        metrics = []
        
        for column in key_columns:
            uniqueness = (data[column].nunique() / len(data)) * 100
            metrics.append(QualityMetric(
                QualityDimension.UNIQUENESS,
                column,
                uniqueness,
                f"{uniqueness:.1f}% of values are unique"
            ))
        
        return metrics
    
    def assess_validity(self, data: pd.DataFrame, rules: Dict[str, Callable]) -> List[QualityMetric]:
        """Assess data validity based on custom rules"""
        metrics = []
        
        for column, rule in rules.items():
            if column in data.columns:
                valid_mask = data[column].apply(rule)
                validity = (valid_mask.sum() / len(data)) * 100
                metrics.append(QualityMetric(
                    QualityDimension.VALIDITY,
                    column,
                    validity,
                    f"{validity:.1f}% of values pass validation"
                ))
        
        return metrics
    
    def generate_quality_report(self, data: pd.DataFrame, key_columns: List[str] = None) -> Dict[str, List[QualityMetric]]:
        """Generate comprehensive quality report"""
        
        key_columns = key_columns or data.columns.tolist()
        
        report = {
            'completeness': self.assess_completeness(data),
            'uniqueness': self.assess_uniqueness(data, key_columns),
        }
        
        # Add validity rules
        validity_rules = {
            'email': lambda x: pd.isna(x) or '@' in str(x),
            'age': lambda x: pd.isna(x) or (18 <= x <= 100),
            'salary': lambda x: pd.isna(x) or x > 0,
        }
        
        report['validity'] = self.assess_validity(data, validity_rules)
        
        return report

# Usage example
def assess_data_quality(data: pd.DataFrame) -> Dict[str, List[QualityMetric]]:
    """Assess quality of employee data"""
    
    assessor = DataQualityAssessor()
    quality_report = assessor.generate_quality_report(
        data, 
        key_columns=['employee_id', 'email']
    )
    
    # Print summary
    for dimension, metrics in quality_report.items():
        print(f"\n{dimension.upper()}:")
        for metric in metrics:
            if metric.score < 90:  # Flag low quality
                print(f"  ⚠️  {metric.column}: {metric.description}")
            else:
                print(f"  ✅ {metric.column}: {metric.description}")
    
    return quality_report
```

### 2. Data Lineage and Tracking
```python
import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class DataTransformation:
    """Record of data transformation"""
    id: str
    timestamp: datetime
    operation: str
    input_columns: List[str]
    output_columns: List[str]
    parameters: Dict[str, Any]
    input_rows: int
    output_rows: int

class DataLineageTracker:
    """Track data lineage through processing pipeline"""
    
    def __init__(self):
        self.transformations: List[DataTransformation] = []
    
    def record_transformation(self,
                             operation: str,
                             input_data: pd.DataFrame,
                             output_data: pd.DataFrame,
                             parameters: Dict[str, Any] = None) -> str:
        """Record a data transformation"""
        
        transformation = DataTransformation(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            operation=operation,
            input_columns=list(input_data.columns),
            output_columns=list(output_data.columns),
            parameters=parameters or {},
            input_rows=len(input_data),
            output_rows=len(output_data)
        )
        
        self.transformations.append(transformation)
        return transformation.id
    
    def get_lineage(self, column: str) -> List[DataTransformation]:
        """Get lineage for a specific column"""
        lineage = []
        
        for transformation in self.transformations:
            if column in transformation.input_columns or column in transformation.output_columns:
                lineage.append(transformation)
        
        return lineage
    
    def export_lineage(self, file_path: str) -> None:
        """Export lineage to JSON file"""
        
        lineage_data = []
        for transformation in self.transformations:
            data = asdict(transformation)
            data['timestamp'] = transformation.timestamp.isoformat()
            lineage_data.append(data)
        
        with open(file_path, 'w') as f:
            json.dump(lineage_data, f, indent=2)

# Decorator for automatic lineage tracking
def track_transformation(lineage_tracker: DataLineageTracker, operation: str):
    """Decorator to automatically track data transformations"""
    
    def decorator(func):
        def wrapper(input_data: pd.DataFrame, *args, **kwargs):
            output_data = func(input_data, *args, **kwargs)
            
            lineage_tracker.record_transformation(
                operation=operation,
                input_data=input_data,
                output_data=output_data,
                parameters={'args': args, 'kwargs': kwargs}
            )
            
            return output_data
        return wrapper
    return decorator

# Usage example
def data_processing_with_lineage():
    """Example of data processing with lineage tracking"""
    
    tracker = DataLineageTracker()
    
    @track_transformation(tracker, "clean_data")
    def clean_data(data: pd.DataFrame) -> pd.DataFrame:
        return data.dropna()
    
    @track_transformation(tracker, "transform_data")
    def transform_data(data: pd.DataFrame) -> pd.DataFrame:
        data['new_column'] = data['existing_column'] * 2
        return data
    
    # Process data
    raw_data = pd.DataFrame({'existing_column': [1, 2, 3, None, 5]})
    cleaned_data = clean_data(raw_data)
    transformed_data = transform_data(cleaned_data)
    
    # Export lineage
    tracker.export_lineage('data/lineage.json')
    
    return transformed_data
```

## Best Practices

### 1. Performance Optimization
```python
import pandas as pd
import numpy as np
from typing import Dict, Any

def optimize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Optimize DataFrame memory usage and performance"""
    
    # Convert object columns to category when appropriate
    for col in df.select_dtypes(include=['object']).columns:
        if df[col].nunique() / len(df) < 0.5:  # Low cardinality
            df[col] = df[col].astype('category')
    
    # Downcast numeric types
    for col in df.select_dtypes(include=['int64']).columns:
        df[col] = pd.to_numeric(df[col], downcast='integer')
    
    for col in df.select_dtypes(include=['float64']).columns:
        df[col] = pd.to_numeric(df[col], downcast='float')
    
    return df

def vectorized_operations(df: pd.DataFrame) -> pd.DataFrame:
    """Use vectorized operations for better performance"""
    
    # BAD: Row-by-row operations
    # for idx, row in df.iterrows():
    #     df.loc[idx, 'new_col'] = row['col1'] + row['col2']
    
    # GOOD: Vectorized operations
    df['new_col'] = df['col1'] + df['col2']
    
    # Use numpy for complex operations
    df['complex_result'] = np.sqrt(df['col1']**2 + df['col2']**2)
    
    return df
```

### 2. Error Handling and Logging
```python
import logging
import pandas as pd
from typing import Optional, Callable, Any

class DataProcessingError(Exception):
    """Custom exception for data processing errors"""
    pass

def safe_data_operation(operation: Callable, data: pd.DataFrame, *args, **kwargs) -> Optional[pd.DataFrame]:
    """Safely execute data operation with error handling"""
    
    try:
        return operation(data, *args, **kwargs)
    except Exception as e:
        logging.error(f"Data operation failed: {str(e)}")
        logging.error(f"Data shape: {data.shape}")
        logging.error(f"Data columns: {list(data.columns)}")
        
        # Optionally save problematic data for debugging
        data.to_csv('error_data.csv', index=False)
        
        raise DataProcessingError(f"Data processing failed: {str(e)}")
```

This comprehensive data processing guide covers ETL patterns, streaming processing, parallel processing, data quality, and best practices for Python data workflows.
