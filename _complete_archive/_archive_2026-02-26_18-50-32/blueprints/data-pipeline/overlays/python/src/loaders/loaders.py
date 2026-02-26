"""
Data Loaders - Database, Warehouse, File
"""

from abc import ABC
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional
import json
import logging

from .base import BaseLoader, LoadMode


logger = logging.getLogger(__name__)


# ============================================================================
# Database Loader
# ============================================================================

class DatabaseLoader(BaseLoader[Dict[str, Any]]):
    """Load data to relational databases."""
    
    def _setup(self):
        self.connection_string = self.config.get("connection_string")
        self.table = self.config["target"]
        self.key_columns = self.config.get("key", [])
        
        from sqlalchemy import create_engine, MetaData, Table
        from sqlalchemy.dialects import postgresql
        
        self._engine = create_engine(self.connection_string)
        self._metadata = MetaData()
        
        # Reflect table schema
        self._table = Table(
            self.table,
            self._metadata,
            autoload_with=self._engine,
        )
    
    def load(self, records: List[Dict[str, Any]]) -> int:
        """Load records to database."""
        if not records:
            return 0
        
        with self._engine.begin() as conn:
            if self.mode == LoadMode.INSERT:
                result = conn.execute(
                    self._table.insert(),
                    records,
                )
                return result.rowcount
            
            elif self.mode == LoadMode.UPSERT:
                return self._upsert(conn, records)
            
            elif self.mode == LoadMode.REPLACE:
                # Delete existing and insert new
                conn.execute(self._table.delete())
                result = conn.execute(
                    self._table.insert(),
                    records,
                )
                return result.rowcount
            
            elif self.mode == LoadMode.APPEND:
                result = conn.execute(
                    self._table.insert(),
                    records,
                )
                return result.rowcount
        
        return 0
    
    def _upsert(self, conn, records: List[Dict]) -> int:
        """Perform upsert (insert or update)."""
        from sqlalchemy.dialects.postgresql import insert
        
        # Build upsert statement
        stmt = insert(self._table).values(records)
        
        # Columns to update
        update_cols = {
            col.name: stmt.excluded[col.name]
            for col in self._table.columns
            if col.name not in self.key_columns
        }
        
        stmt = stmt.on_conflict_do_update(
            index_elements=self.key_columns,
            set_=update_cols,
        )
        
        result = conn.execute(stmt)
        return result.rowcount
    
    @contextmanager
    def transaction(self):
        """Provide transaction context."""
        with self._engine.begin() as conn:
            yield conn
    
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
# Data Warehouse Loader (Snowflake/BigQuery/Redshift)
# ============================================================================

class WarehouseLoader(BaseLoader[Dict[str, Any]]):
    """Load data to data warehouses."""
    
    def _setup(self):
        self.warehouse_type = self.config.get("warehouse", "snowflake")
        self.table = self.config["target"]
        self.schema = self.config.get("schema", "public")
        self.key_columns = self.config.get("key", [])
        
        if self.warehouse_type == "snowflake":
            self._setup_snowflake()
        elif self.warehouse_type == "bigquery":
            self._setup_bigquery()
        elif self.warehouse_type == "redshift":
            self._setup_redshift()
    
    def _setup_snowflake(self):
        """Setup Snowflake connection."""
        import snowflake.connector
        
        self._conn = snowflake.connector.connect(
            account=self.config.get("account"),
            user=self.config.get("user"),
            password=self.config.get("password"),
            warehouse=self.config.get("warehouse"),
            database=self.config.get("database"),
            schema=self.schema,
        )
    
    def _setup_bigquery(self):
        """Setup BigQuery client."""
        from google.cloud import bigquery
        
        self._client = bigquery.Client(
            project=self.config.get("project"),
        )
        self._dataset = self.config.get("dataset")
    
    def _setup_redshift(self):
        """Setup Redshift connection."""
        import redshift_connector
        
        self._conn = redshift_connector.connect(
            host=self.config.get("host"),
            database=self.config.get("database"),
            port=self.config.get("port", 5439),
            user=self.config.get("user"),
            password=self.config.get("password"),
        )
    
    def load(self, records: List[Dict[str, Any]]) -> int:
        """Load records to warehouse."""
        if not records:
            return 0
        
        if self.warehouse_type == "snowflake":
            return self._load_snowflake(records)
        elif self.warehouse_type == "bigquery":
            return self._load_bigquery(records)
        elif self.warehouse_type == "redshift":
            return self._load_redshift(records)
        
        return 0
    
    def _load_snowflake(self, records: List[Dict]) -> int:
        """Load to Snowflake using MERGE."""
        import pandas as pd
        from snowflake.connector.pandas_tools import write_pandas
        
        df = pd.DataFrame(records)
        
        # Use write_pandas for efficient loading
        success, nchunks, nrows, _ = write_pandas(
            self._conn,
            df,
            self.table,
            schema=self.schema,
            auto_create_table=False,
        )
        
        return nrows if success else 0
    
    def _load_bigquery(self, records: List[Dict]) -> int:
        """Load to BigQuery."""
        from google.cloud.bigquery import LoadJobConfig, WriteDisposition
        
        table_ref = f"{self._dataset}.{self.table}"
        
        config = LoadJobConfig()
        config.write_disposition = (
            WriteDisposition.WRITE_TRUNCATE
            if self.mode == LoadMode.REPLACE
            else WriteDisposition.WRITE_APPEND
        )
        
        job = self._client.load_table_from_json(
            records,
            table_ref,
            job_config=config,
        )
        job.result()  # Wait for completion
        
        return len(records)
    
    def _load_redshift(self, records: List[Dict]) -> int:
        """Load to Redshift."""
        cursor = self._conn.cursor()
        
        # Build INSERT statement
        columns = records[0].keys()
        placeholders = ", ".join(["%s"] * len(columns))
        column_str = ", ".join(columns)
        
        insert_sql = f"""
            INSERT INTO {self.schema}.{self.table} ({column_str})
            VALUES ({placeholders})
        """
        
        # Execute in batches
        values = [tuple(r[c] for c in columns) for r in records]
        cursor.executemany(insert_sql, values)
        self._conn.commit()
        
        return len(records)


# ============================================================================
# File Loader (Local, S3, GCS)
# ============================================================================

class FileLoader(BaseLoader[Dict[str, Any]]):
    """Load data to files."""
    
    def _setup(self):
        self.target_path = self.config["target"]
        self.file_format = self.config.get("format", "parquet")
        self.compression = self.config.get("compression", "snappy")
        self.partition_by = self.config.get("partition_by", [])
    
    def load(self, records: List[Dict[str, Any]]) -> int:
        """Load records to file(s)."""
        if not records:
            return 0
        
        import pandas as pd
        df = pd.DataFrame(records)
        
        if self.target_path.startswith("s3://"):
            return self._load_s3(df)
        elif self.target_path.startswith("gs://"):
            return self._load_gcs(df)
        else:
            return self._load_local(df)
    
    def _load_local(self, df) -> int:
        """Load to local file system."""
        from pathlib import Path
        
        path = Path(self.target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if self.file_format == "parquet":
            df.to_parquet(
                path,
                compression=self.compression,
                index=False,
            )
        elif self.file_format == "csv":
            df.to_csv(path, index=False)
        elif self.file_format == "json":
            df.to_json(path, orient="records", lines=True)
        
        return len(df)
    
    def _load_s3(self, df) -> int:
        """Load to S3."""
        import pyarrow as pa
        import pyarrow.parquet as pq
        from pyarrow import fs
        
        if self.file_format == "parquet":
            table = pa.Table.from_pandas(df)
            
            if self.partition_by:
                pq.write_to_dataset(
                    table,
                    root_path=self.target_path,
                    partition_cols=self.partition_by,
                    filesystem=fs.S3FileSystem(),
                )
            else:
                pq.write_table(
                    table,
                    self.target_path,
                    filesystem=fs.S3FileSystem(),
                )
        else:
            # For other formats, use boto3
            import boto3
            import io
            from urllib.parse import urlparse
            
            parsed = urlparse(self.target_path)
            bucket = parsed.netloc
            key = parsed.path.lstrip("/")
            
            s3 = boto3.client("s3")
            
            if self.file_format == "csv":
                buffer = io.StringIO()
                df.to_csv(buffer, index=False)
                s3.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())
            elif self.file_format == "json":
                buffer = io.StringIO()
                df.to_json(buffer, orient="records", lines=True)
                s3.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())
        
        return len(df)
    
    def _load_gcs(self, df) -> int:
        """Load to Google Cloud Storage."""
        from google.cloud import storage
        from urllib.parse import urlparse
        import io
        
        parsed = urlparse(self.target_path)
        bucket_name = parsed.netloc
        blob_path = parsed.path.lstrip("/")
        
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        
        if self.file_format == "parquet":
            buffer = io.BytesIO()
            df.to_parquet(buffer, compression=self.compression, index=False)
            buffer.seek(0)
            blob.upload_from_file(buffer, content_type="application/octet-stream")
        elif self.file_format == "csv":
            blob.upload_from_string(df.to_csv(index=False), content_type="text/csv")
        elif self.file_format == "json":
            blob.upload_from_string(
                df.to_json(orient="records", lines=True),
                content_type="application/json",
            )
        
        return len(df)


# ============================================================================
# Delta Lake Loader
# ============================================================================

class DeltaLakeLoader(BaseLoader[Dict[str, Any]]):
    """Load data to Delta Lake."""
    
    def _setup(self):
        self.target_path = self.config["target"]
        self.key_columns = self.config.get("key", [])
        self.partition_by = self.config.get("partition_by", [])
    
    def load(self, records: List[Dict[str, Any]]) -> int:
        """Load records to Delta Lake."""
        if not records:
            return 0
        
        import pandas as pd
        from deltalake import DeltaTable, write_deltalake
        
        df = pd.DataFrame(records)
        
        if self.mode == LoadMode.UPSERT and self.key_columns:
            return self._merge_delta(df)
        else:
            mode = "overwrite" if self.mode == LoadMode.REPLACE else "append"
            
            write_deltalake(
                self.target_path,
                df,
                mode=mode,
                partition_by=self.partition_by or None,
            )
            
            return len(df)
    
    def _merge_delta(self, df) -> int:
        """Merge (upsert) into Delta table."""
        from deltalake import DeltaTable
        import pyarrow as pa
        
        dt = DeltaTable(self.target_path)
        
        # Build merge predicate
        predicate = " AND ".join([
            f"target.{col} = source.{col}"
            for col in self.key_columns
        ])
        
        # Convert to PyArrow for merge
        source = pa.Table.from_pandas(df)
        
        (
            dt.merge(
                source,
                predicate=predicate,
                source_alias="source",
                target_alias="target",
            )
            .when_matched_update_all()
            .when_not_matched_insert_all()
            .execute()
        )
        
        return len(df)


# ============================================================================
# Loader Registry
# ============================================================================

LOADERS = {
    "database": DatabaseLoader,
    "warehouse": WarehouseLoader,
    "file": FileLoader,
    "delta": DeltaLakeLoader,
}


def create_loader(config: Dict[str, Any]) -> BaseLoader:
    """Create loader from config."""
    loader_type = config.get("type", "database")
    
    if loader_type not in LOADERS:
        raise ValueError(f"Unknown loader type: {loader_type}")
    
    mode = LoadMode(config.get("mode", "upsert"))
    batch_size = config.get("batch_size", 1000)
    
    return LOADERS[loader_type](config, mode=mode, batch_size=batch_size)
