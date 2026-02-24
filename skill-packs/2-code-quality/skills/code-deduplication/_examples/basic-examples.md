# Code Deduplication — Basic Examples

## Extract Shared Function

**JavaScript:**
```javascript
// ❌ Duplicated in two services
// user-service.js
function formatUserDisplay(user) {
  return `${user.firstName} ${user.lastName}`.trim().toUpperCase();
}
// admin-service.js
function formatAdminDisplay(admin) {
  return `${admin.firstName} ${admin.lastName}`.trim().toUpperCase();
}

// ✅ Extracted to shared/format.js
export function formatFullName(person) {
  return `${person.firstName} ${person.lastName}`.trim().toUpperCase();
}
```

## Parameterize Near-Duplicates

**Python:**
```python
# ❌ Two functions that differ only by filter
def get_active_users(users):
    return [u for u in users if u.status == "active"]

def get_suspended_users(users):
    return [u for u in users if u.status == "suspended"]

# ✅ Parameterized
def get_users_by_status(users, status):
    return [u for u in users if u.status == status]
```

## Template Method for Structural Duplication

**Go:**
```go
// ❌ Same fetch-decode-validate pattern in two handlers
func GetUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    user, err := userRepo.Find(id)
    if err != nil { respondError(w, err); return }
    if user == nil { respondNotFound(w, "user"); return }
    respondJSON(w, user)
}
func GetOrder(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    order, err := orderRepo.Find(id)
    if err != nil { respondError(w, err); return }
    if order == nil { respondNotFound(w, "order"); return }
    respondJSON(w, order)
}

// ✅ Generic handler
func GetByID[T any](repo Repository[T], resourceName string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        id := chi.URLParam(r, "id")
        item, err := repo.Find(id)
        if err != nil { respondError(w, err); return }
        if item == nil { respondNotFound(w, resourceName); return }
        respondJSON(w, item)
    }
}
```

## Detect with Tooling

```bash
# JavaScript: find clones
npx jscpd src/ --min-lines 5 --reporters consoleFull

# Python: find duplicates
pylint --disable=all --enable=duplicate-code src/

# Any language: PMD copy-paste detector
pmd cpd --minimum-tokens 50 --dir src/ --language javascript
```

## When to Use
- "Find duplicate code in this project"
- "These two functions are almost identical"
- "Extract shared logic into a utility"
- "How much duplication does this codebase have?"
