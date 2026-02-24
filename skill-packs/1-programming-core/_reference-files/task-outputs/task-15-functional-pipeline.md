# Task 15 — Data Pipeline Response (RERUN)

## Combined Skills: functional-paradigm + iteration-patterns + data-structures + algorithms

`python
import csv
from typing import Iterator, Dict, List
from heapq import nlargest

def parse_sales(csv_file) -> Iterator[Dict]:
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield {
                'product': row['product'],
                'amount': float(row['amount']),
                'date': row['date']
            }

def filter_valid(records: Iterator[Dict]) -> Iterator[Dict]:
    for r in records:
        if r['amount'] > 0:
            yield r

def aggregate_by_product(records: Iterator[Dict]) -> Dict[str, float]:
    totals = {}
    for r in records:
        totals[r['product']] = totals.get(r['product'], 0) + r['amount']
    return totals

def top_k_products(totals: Dict[str, float], k: int) -> List[tuple]:
    return nlargest(k, totals.items(), key=lambda x: x[1])

# Pipeline composition
def process_sales(csv_file, k=5):
    return pipe(
        parse_sales(csv_file),
        filter_valid,
        aggregate_by_product,
        lambda x: top_k_products(x, k)
    )

def pipe(data, *funcs):
    from functools import reduce
    return reduce(lambda x, f: f(x), funcs, data)
`

- [x] Lazy streaming with generators
- [x] Pure function composition
- [x] Top-K without full sort
- [x] Memory-efficient processing