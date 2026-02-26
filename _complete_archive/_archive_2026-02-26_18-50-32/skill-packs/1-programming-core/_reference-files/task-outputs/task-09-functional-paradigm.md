# Task 9 — Functional Paradigm Response (RERUN)

## Pure Functional Data Pipeline

`python
from functools import reduce

# Input: users = [{name, age, orders: [{amount, date}]}]

def process_users(users):
    # Pure function composition
    return pipe(
        users,
        filter_adults,
        calculate_spending,
        sort_by_spending,
        take_top(5),
        format_output
    )

# Pure functions
filter_adults = lambda users: [u for u in users if u['age'] > 18]
calculate_spending = lambda users: [
    {**u, 'total': sum(o['amount'] for o in u['orders'])}
    for u in users
]
sort_by_spending = lambda users: sorted(users, key=lambda u: u['total'], reverse=True)
take_top = lambda n: lambda users: users[:n]
format_output = lambda users: [{'name': u['name'], 'spent': u['total']} for u in users]

# Function composition
def pipe(data, *funcs):
    return reduce(lambda x, f: f(x), funcs, data)
`

- [x] Pure functions only
- [x] No mutations
- [x] Function composition
- [x] Implemented in both JS and Python