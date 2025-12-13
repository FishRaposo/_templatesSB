# {{PROJECT_NAME}} - Data Pipeline Reference Project

A production-ready data pipeline built with Python, demonstrating best practices for ETL, data validation, incremental processing, and observability.

## Features

- **ETL Framework**: Modular extract, transform, load pipeline
- **Data Validation**: Schema validation with Pydantic and Great Expectations
- **Incremental Processing**: Efficient delta processing with watermarks
- **Multiple Sources**: Support for APIs, databases, files, and streaming
- **Observability**: Logging, metrics, and alerting
- **Orchestration**: Prefect/Airflow ready task definitions

## Tech Stack

- **Core**: Python 3.11+
- **Data**: pandas, polars, DuckDB
- **Validation**: Pydantic, Great Expectations
- **Storage**: PostgreSQL, S3/MinIO, Delta Lake
- **Orchestration**: Prefect 2.x
- **Testing**: pytest, hypothesis

## Project Structure

```
{{PROJECT_NAME}}/
├── src/
│   ├── {{PROJECT_SLUG}}/
│   │   ├── __init__.py
│   │   ├── config.py           # Configuration management
│   │   ├── cli.py              # CLI interface
│   │   │
│   │   ├── extractors/         # Data extraction
│   │   │   ├── base.py         # Base extractor class
│   │   │   ├── api.py          # REST API extractor
│   │   │   ├── database.py     # Database extractor
│   │   │   ├── file.py         # File/S3 extractor
│   │   │   └── stream.py       # Kafka/streaming extractor
│   │   │
│   │   ├── transformers/       # Data transformation
│   │   │   ├── base.py         # Base transformer class
│   │   │   ├── cleaners.py     # Data cleaning transforms
│   │   │   ├── enrichers.py    # Data enrichment
│   │   │   ├── aggregators.py  # Aggregation transforms
│   │   │   └── validators.py   # Validation transforms
│   │   │
│   │   ├── loaders/            # Data loading
│   │   │   ├── base.py         # Base loader class
│   │   │   ├── database.py     # Database loader
│   │   │   ├── warehouse.py    # Data warehouse loader
│   │   │   └── file.py         # File/S3 loader
│   │   │
│   │   ├── models/             # Data models
│   │   │   ├── schemas.py      # Pydantic schemas
│   │   │   └── entities.py     # Domain entities
│   │   │
│   │   ├── pipelines/          # Pipeline definitions
│   │   │   ├── base.py         # Base pipeline class
│   │   │   ├── customer_pipeline.py
│   │   │   └── events_pipeline.py
│   │   │
│   │   ├── orchestration/      # Orchestration
│   │   │   ├── flows.py        # Prefect flows
│   │   │   └── tasks.py        # Prefect tasks
│   │   │
│   │   └── utils/              # Utilities
│   │       ├── logging.py
│   │       ├── metrics.py
│   │       └── state.py        # State management
│   │
│   └── tests/
│       ├── conftest.py
│       ├── unit/
│       ├── integration/
│       └── fixtures/
│
├── pipelines/                   # Pipeline configurations
│   ├── customer_sync.yaml
│   └── events_ingest.yaml
│
├── great_expectations/          # Data quality checks
├── docker/
├── pyproject.toml
└── Dockerfile
```

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure
cp .env.example .env

# Run pipeline
python -m {{PROJECT_SLUG}} run --pipeline customer_sync

# Run with Prefect
prefect deployment run 'customer-sync/daily'
```

## Configuration

```yaml
# pipelines/customer_sync.yaml
pipeline:
  name: customer_sync
  schedule: "0 */4 * * *"  # Every 4 hours
  
extractor:
  type: api
  source: https://api.example.com/customers
  auth:
    type: bearer
    token_env: API_TOKEN
  pagination:
    type: cursor
    page_size: 100
  incremental:
    field: updated_at
    watermark_key: customer_sync_watermark

transformers:
  - type: clean
    operations:
      - trim_strings
      - normalize_emails
      - remove_duplicates
  
  - type: validate
    schema: CustomerSchema
    on_error: skip_and_log
  
  - type: enrich
    lookups:
      - table: regions
        on: region_code
        fields: [region_name, timezone]

loader:
  type: database
  target: customers
  mode: upsert
  key: [customer_id]
  batch_size: 1000
```

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=src --cov-report=html

# Property-based tests
pytest tests/ -k "hypothesis"
```

## License

MIT License
