# Complete Example: CLI-Focused Skill

This is a complete, production-ready example of a CLI-focused skill for processing CSV data.

## Directory Structure

```
processing-csv-data/
├── SKILL.md
├── README.md
├── config.json
└── _examples/
    ├── basic-examples.md
    └── advanced-examples.md
```

## SKILL.md

```markdown
---
name: processing-csv-data
description: Use this skill when processing, transforming, filtering, or analyzing CSV files. This includes converting CSV to other formats, extracting specific columns, aggregating data, cleaning messy CSV files, or generating reports from CSV data sources.
---

# CSV Data Processing

I'll help you process, transform, and analyze CSV data using CLI tools and Node.js scripts.

# Core Approach

My approach focuses on:
1. Understanding the CSV structure (headers, delimiters, encoding)
2. Choosing the right tool for the task (CLI for simple, Node.js for complex)
3. Implementing efficient transformations
4. Validating output data integrity

# Step-by-Step Instructions

## 1. Analyze the CSV Structure

First, I'll examine the file to understand its format:

- Check file size and line count
- Identify headers and delimiter
- Detect encoding issues
- Sample first few rows

**CLI Tools:**
- `head -n 5 data.csv` - Preview first rows
- `wc -l data.csv` - Count total rows
- `file data.csv` - Detect encoding

## 2. Process the Data

For simple operations, use CLI tools directly:

```bash
# Extract specific columns (1st and 3rd)
cut -d',' -f1,3 data.csv > output.csv

# Filter rows matching a pattern
grep "active" data.csv > active-records.csv

# Sort by second column
sort -t',' -k2 data.csv > sorted.csv

# Remove duplicate rows
sort -u data.csv > unique.csv
```

For complex transformations, use Node.js:

```javascript
#!/usr/bin/env node
import { createReadStream, createWriteStream } from 'fs';
import { parse } from 'csv-parse';
import { stringify } from 'csv-stringify';

const input = createReadStream('data.csv');
const output = createWriteStream('output.csv');

const parser = parse({ columns: true, trim: true });
const stringifier = stringify({ header: true });

parser.on('data', (record) => {
  // Transform: filter active users and uppercase names
  if (record.status === 'active') {
    record.name = record.name.toUpperCase();
    stringifier.write(record);
  }
});

input.pipe(parser);
stringifier.pipe(output);
```

## 3. Validate the Output

After processing, verify the results:

```bash
# Compare row counts
echo "Input rows: $(wc -l < data.csv)"
echo "Output rows: $(wc -l < output.csv)"

# Check for empty fields
grep ",," output.csv | head -5

# Preview output
head -n 10 output.csv
```

# Best Practices

- Always preview data before bulk processing
- Preserve original files; write to new output files
- Handle quoted fields and embedded commas properly
- Use streaming for large files (avoid loading entire file into memory)
- Validate output row counts against expectations
- Document any data transformations applied

# Validation Checklist

When processing CSV data, verify:
- [ ] Output file has correct headers
- [ ] Row count matches expectations (filtered or full)
- [ ] No data corruption (check random samples)
- [ ] Encoding is preserved correctly
- [ ] Delimiter is consistent throughout
- [ ] No trailing whitespace or empty rows

# Troubleshooting

## Issue: Malformed CSV with embedded commas

**Symptoms**: Columns shift when fields contain commas

**Solution**:
- Use a proper CSV parser (not `cut` or `split`)
- Node.js `csv-parse` handles quoted fields automatically
- Check if fields are properly quoted in the source

## Issue: Large file runs out of memory

**Symptoms**: Node.js process crashes with heap allocation error

**Solution**:
- Use streaming instead of `readFile`
- Process row by row with `csv-parse` streams
- For very large files, use `split` command to chunk first

## Issue: Character encoding problems

**Symptoms**: Special characters appear garbled

**Solution**:
- Check encoding: `file data.csv`
- Convert if needed: `iconv -f ISO-8859-1 -t UTF-8 data.csv > data-utf8.csv`
- Specify encoding in Node.js: `createReadStream('data.csv', { encoding: 'utf-8' })`

# Supporting Files

- See `./_examples/basic-examples.md` for simple CSV operations
- See `./_examples/advanced-examples.md` for complex transformations

## Related Skills

- **data-types** - Understanding data type conversions during CSV processing
- **iteration-patterns** - Efficient iteration over large datasets
- → **5-error-handling**: exception-handling (for robust file I/O error handling)

Remember: Always stream large CSV files — never load the entire file into memory!
```

## README.md

```markdown
# Processing CSV Data

Process, transform, filter, and analyze CSV files using CLI tools and Node.js.

## Quick Start

1. Analyze your CSV: `head -n 5 data.csv`
2. Choose your approach: CLI for simple ops, Node.js for complex transforms
3. Process the data
4. Validate the output

## When This Skill Activates

- "Process this CSV file"
- "Convert CSV to JSON"
- "Filter rows where status is active"
- "Extract columns from this spreadsheet"
- "Clean up this messy CSV"

## Key Commands

| Command | Purpose |
|---------|---------|
| `head -n N file.csv` | Preview first N rows |
| `wc -l file.csv` | Count rows |
| `cut -d',' -fN file.csv` | Extract column N |
| `sort -t',' -kN file.csv` | Sort by column N |
| `grep "pattern" file.csv` | Filter rows |

## Dependencies

- Node.js 18+ (for complex transforms)
- `npm install csv-parse csv-stringify` (for Node.js scripts)
```

## config.json

```json
{
  "agent_support": {
    "claude": true,
    "roo": true,
    "generic": true
  },
  "triggers": {
    "keywords": [
      "csv",
      "spreadsheet",
      "comma-separated",
      "tsv",
      "data file",
      "columns",
      "rows"
    ],
    "patterns": [
      "process csv",
      "convert csv",
      "filter csv",
      "parse csv",
      "transform data file"
    ],
    "file_types": [
      ".csv",
      ".tsv"
    ]
  },
  "requirements": {
    "tools": [],
    "permissions": [
      "file_read",
      "file_write"
    ],
    "memory": false
  },
  "examples": {
    "simple": [
      {
        "query": "Extract the name and email columns from users.csv",
        "description": "Column extraction using cut or Node.js"
      },
      {
        "query": "How many rows are in this CSV?",
        "description": "Quick row count with wc -l"
      }
    ],
    "complex": [
      {
        "query": "Filter orders.csv to only include orders over $100, then group by customer and sum the totals",
        "context": "Large file with headers: order_id, customer_id, amount, date",
        "expected_behavior": "Use Node.js streaming to filter and aggregate"
      }
    ]
  }
}
```
