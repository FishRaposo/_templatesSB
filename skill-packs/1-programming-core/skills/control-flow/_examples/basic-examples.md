# Control Flow Examples

## Early Returns / Guard Clauses

**JavaScript:**
```javascript
function processUser(user) {
    if (!user) return { error: 'No user provided' };
    if (!user.email) return { error: 'Email required' };
    if (!user.isActive) return { error: 'User not active' };
    return { success: true, user: sanitizeUser(user) };
}
```

**Python:**
```python
def process_user(user):
    if not user: return {"error": "No user provided"}
    if not user.get("email"): return {"error": "Email required"}
    if not user.get("is_active"): return {"error": "User not active"}
    return {"success": True, "user": sanitize_user(user)}
```

## State Machine

**JavaScript:**
```javascript
const transitions = {
    pending:   { validate: 'validated' },
    validated: { pay: 'paid' },
    paid:      { ship: 'shipped' },
};
function transition(state, event) {
    return transitions[state]?.[event] ?? state;
}
```

**Python:**
```python
transitions = {
    "pending":   {"validate": "validated"},
    "validated": {"pay": "paid"},
    "paid":      {"ship": "shipped"},
}
def transition(state, event):
    return transitions.get(state, {}).get(event, state)
```

## Error Handling

**JavaScript:**
```javascript
async function fetchUserData(userId) {
    try {
        const [user, profile] = await Promise.all([
            getUser(userId), getProfile(userId)
        ]);
        return { user, profile };
    } catch (error) {
        console.error('Failed:', error);
        throw error;
    }
}
```

**Python:**
```python
import asyncio

async def fetch_user_data(user_id):
    try:
        user, profile = await asyncio.gather(
            get_user(user_id), get_profile(user_id)
        )
        return {"user": user, "profile": profile}
    except Exception as e:
        print(f"Failed: {e}")
        raise
```

## When to Use
- Design control flow for this process
- Handle multiple conditions cleanly
- Manage async operations properly