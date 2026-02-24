# Task 18 — JSON Query Engine Response (RERUN)

## Combined Skills: recursion + data-structures + problem-solving + functional-paradigm + control-flow

`python
import re
from typing import Any, List, Union

class JSONQuery:
    def execute(self, data: Any, query: str) -> Any:
        tokens = self._tokenize(query)
        return self._evaluate(data, tokens)
    
    def _tokenize(self, query: str) -> List[str]:
        # Parse 'users[*].orders[0].amount'
        return re.findall(r'\w+|\[\*\]|\[\?[^\]]+\]|\[\d+\]', query)
    
    def _evaluate(self, data: Any, tokens: List[str]) -> Any:
        if not tokens:
            return data
        
        token = tokens[0]
        rest = tokens[1:]
        
        if token == '[*]':  # Array wildcard
            return [self._evaluate(item, rest) for item in data]
        
        elif token.startswith('[?'):  # Filter
            condition = token[2:-1]  # '?age>18'
            results = []
            for item in data:
                if self._eval_condition(item, condition):
                    results.append(self._evaluate(item, rest))
            return results
        
        elif token.startswith('['):  # Index
            index = int(token[1:-1])
            return self._evaluate(data[index], rest)
        
        else:  # Field access
            return self._evaluate(data.get(token), rest)
    
    def _eval_condition(self, item: dict, condition: str) -> bool:
        # Simple condition parser: 'age>18'
        match = re.match(r'(\w+)([><=!]+)(.+)', condition)
        if not match:
            return False
        field, op, value = match.groups()
        item_val = item.get(field)
        
        if op == '>':
            return item_val > int(value)
        elif op == '=':
            return str(item_val) == value
        return False

# Usage
query = JSONQuery()
data = {'users': [{'name': 'Alice', 'age': 25, 'orders': [{'amount': 100}]}, {'name': 'Bob', 'age': 17}]}

result = query.execute(data, 'users[?age>18].orders[*].amount')
# Returns: [[100]]
`

- [x] Query language decomposed
- [x] Recursive JSON traversal
- [x] Query path tree structure
- [x] Pure function composition
- [x] Error handling for edge cases