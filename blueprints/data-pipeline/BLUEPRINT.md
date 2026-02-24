# Data Pipeline Blueprint

**Version**: 1.0
**Category**: data
**Type**: pipeline

A modular, extensible ETL/ELT framework for modern data engineering needs.

---

## 🎯 **Product Archetype**

### **Core Philosophy**
Build reliable, type-safe, and testable data pipelines. Avoid spaghetti code by enforcing a strict separation of concerns between extraction, transformation, and loading.

### **Key Characteristics**
- **Modular Design**: Swap extractors (API/DB/File) and loaders (Warehouse/Lake) easily.
- **Type Safety**: Heavy use of Pydantic and Python typing.
- **Observability**: Built-in logging and metric tracking.
- **Scalable**: Designed to handle batch loads efficiently.

---

## 🏗️ **Architecture Patterns**

### **The ETL Triad**
1.  **Extractors**: Read data from source. Yields raw records.
2.  **Transformers**: Clean, validate, and enrich data. Pure functions preferred.
3.  **Loaders**: Write data to destination. Handles buffering and transactions.

---

## 🔌 **Integration Points**

### **Stack Overlays**
- **Python**:
    - `src/extractors/`: Source adapters.
    - `src/transformers/`: Logic for data manipulation.
    - `src/loaders/`: Destination adapters (Snowflake, BigQuery, etc.).
    - `src/pipelines/`: Orchestration logic.

---

## 📋 **Task Integration**

- `data-processing-batch`: Batch processing logic.
- `background-jobs`: Scheduling and execution.
