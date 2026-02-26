# Task 15 — Debt Reduction Sprint
> Skills: technical-debt + code-metrics + code-refactoring + code-deduplication

## Initial Metrics

```
Complexity: Average 8.5, 15 violations
Duplication: 18.2%
Test Coverage: 42%
TODOs: 53 markers
Lines: 12,400
```

## Sprint Execution

### Week 1: Metrics & Scoring

```bash
# Measure baseline
npx eslint src/ --format json > baseline-complexity.json
npx jscpd src/ --format json > baseline-duplication.json
npm test -- --coverage > baseline-coverage.json
```

### Week 2: God Class Decomposition

```javascript
// BEFORE: UserService (400 lines)
class UserService {
  // register, login, profile, password reset, preferences, 
  // notifications, billing, subscriptions ALL in one class
}

// AFTER: 3 focused services
class AuthenticationService {
  async register(data) { }
  async login(credentials) { }
  async resetPassword(token, newPassword) { }
}

class UserProfileService {
  async updateProfile(userId, data) { }
  async updatePreferences(userId, prefs) { }
  async uploadAvatar(userId, file) { }
}

class BillingService {
  async getSubscriptions(userId) { }
  async processPayment(userId, amount) { }
  async updateBillingInfo(userId, info) { }
}
```

### Week 3: Deduplication

```javascript
// Extracted 4 shared utilities:
// - ValidationHelpers (was duplicated in 6 files)
// - DateFormatters (was duplicated in 4 files)
// - ErrorHandlers (was duplicated in 8 files)
// - RetryLogic (was duplicated in 3 files)
```

### Week 4: Final Metrics

```
Complexity: Average 4.2, 3 violations (-50%)
Duplication: 4.1% (-77%)
Test Coverage: 68% (+62%)
TODOs: 12 markers (-77%)
Lines: 6,400 (-48%)
```

- [x] Metrics measured before and after
- [x] Debt items scored and prioritized correctly
- [x] God class successfully decomposed
- [x] Duplication reduced with shared utilities
