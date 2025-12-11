<!--
File: authentication-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: authentication-pattern.tpl.md
# PURPOSE: Generic authentication design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Authentication Pattern

## Overview
Authentication is crucial for securing applications and protecting user data. This pattern provides a comprehensive approach to authentication with multiple strategies, token management, and security best practices.

## Core Design Pattern

### 1. Authentication Architecture

#### Authentication Strategies
- **JWT (JSON Web Tokens)**: Stateless token-based authentication
- **Session-based**: Server-side session management
- **OAuth 2.0**: Third-party authentication (Google, GitHub, etc.)
- **API Key**: Simple key-based authentication for services
- **Basic Auth**: Username/password authentication
- **Multi-factor**: Additional security layer

#### Core Components
- **Auth Manager**: Central authentication coordinator
- **Token Manager**: JWT token creation, validation, refresh
- **User Store**: User data and credential storage
- **Password Manager**: Secure password hashing and verification
- **Auth Middleware**: Request authentication and authorization
- **Security Utils**: Encryption, hashing, random token generation

### 2. Pseudocode Implementation

```pseudocode
class AuthManager:
    function __init__(user_store, token_manager, password_manager):
        self.user_store = user_store
        self.token_manager = token_manager
        self.password_manager = password_manager
        self.strategies = {}
    
    function register_strategy(name, strategy):
        self.strategies[name] = strategy
    
    function authenticate(strategy_name, credentials):
        strategy = self.strategies.get(strategy_name)
        if not strategy:
            raise AuthError(f"Unknown auth strategy: {strategy_name}")
        
        return strategy.authenticate(credentials)
    
    function login(username, password):
        # Find user
        user = self.user_store.find_by_username(username)
        if not user:
            raise AuthError("Invalid credentials")
        
        # Verify password
        if not self.password_manager.verify(password, user.password_hash):
            raise AuthError("Invalid credentials")
        
        # Generate tokens
        access_token = self.token_manager.generate_access_token(user)
        refresh_token = self.token_manager.generate_refresh_token(user)
        
        # Update last login
        self.user_store.update_last_login(user.id)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": self.sanitize_user(user),
            "expires_in": self.token_manager.access_token_expiry
        }
    
    function refresh_token(refresh_token):
        # Validate refresh token
        token_data = self.token_manager.validate_refresh_token(refresh_token)
        if not token_data:
            raise AuthError("Invalid refresh token")
        
        # Get user
        user = self.user_store.find_by_id(token_data.user_id)
        if not user:
            raise AuthError("User not found")
        
        # Generate new access token
        new_access_token = self.token_manager.generate_access_token(user)
        
        return {
            "access_token": new_access_token,
            "expires_in": self.token_manager.access_token_expiry
        }
    
    function logout(access_token):
        # Add token to blacklist
        self.token_manager.blacklist_token(access_token)
    
    function sanitize_user(user):
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at,
            "last_login": user.last_login
        }

class TokenManager:
    function __init__(secret_key, access_expiry=3600, refresh_expiry=86400):
        self.secret_key = secret_key
        self.access_token_expiry = access_expiry
        self.refresh_token_expiry = refresh_expiry
        self.blacklisted_tokens = set()
    
    function generate_access_token(user):
        payload = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "type": "access",
            "iat": current_time(),
            "exp": current_time() + self.access_token_expiry
        }
        
        return self.encode_token(payload)
    
    function generate_refresh_token(user):
        payload = {
            "user_id": user.id,
            "type": "refresh",
            "iat": current_time(),
            "exp": current_time() + self.refresh_token_expiry
        }
        
        return self.encode_token(payload)
    
    function validate_access_token(token):
        if token in self.blacklisted_tokens:
            return None
        
        payload = self.decode_token(token)
        if not payload or payload.get("type") != "access":
            return None
        
        return payload
    
    function validate_refresh_token(token):
        payload = self.decode_token(token)
        if not payload or payload.get("type") != "refresh":
            return None
        
        return payload
    
    function blacklist_token(token):
        self.blacklisted_tokens.add(token)
    
    function encode_token(payload):
        # Platform-specific JWT encoding
        # This would use JWT libraries for each language
        pass
    
    function decode_token(token):
        # Platform-specific JWT decoding
        # This would use JWT libraries for each language
        pass

class PasswordManager:
    function __init__(rounds=12):
        self.rounds = rounds
    
    function hash(password):
        # Use bcrypt or similar secure hashing
        salt = generate_salt()
        hash_value = hash_password(password, salt, self.rounds)
        return f"{salt}${hash_value}"
    
    function verify(password, hash_value):
        salt, stored_hash = hash_value.split("$")
        computed_hash = hash_password(password, salt, self.rounds)
        return secure_compare(computed_hash, stored_hash)
    
    function generate_strong_password(length=16):
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return generate_random_string(characters, length)

class UserStore:
    function find_by_username(username):
        # Database lookup implementation
        pass
    
    function find_by_id(user_id):
        # Database lookup implementation
        pass
    
    function create_user(user_data):
        # Hash password before storing
        password_manager = PasswordManager()
        hashed_password = password_manager.hash(user_data.password)
        
        user = {
            "id": generate_id(),
            "username": user_data.username,
            "email": user_data.email,
            "password_hash": hashed_password,
            "roles": user_data.roles or ["user"],
            "created_at": current_time(),
            "last_login": None
        }
        
        return self.save(user)
    
    function update_last_login(user_id):
        # Update last login timestamp
        pass

class AuthMiddleware:
    function __init__(auth_manager, token_manager):
        self.auth_manager = auth_manager
        self.token_manager = token_manager
    
    function authenticate_request(request):
        # Extract token from header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise AuthError("Missing or invalid authorization header")
        
        token = auth_header.split(" ")[1]
        
        # Validate token
        token_data = self.token_manager.validate_access_token(token)
        if not token_data:
            raise AuthError("Invalid or expired token")
        
        # Get user
        user = self.auth_manager.user_store.find_by_id(token_data.user_id)
        if not user:
            raise AuthError("User not found")
        
        # Add user to request context
        request.user = user
        request.user_roles = token_data.roles
        
        return request

class JWTStrategy:
    function authenticate(credentials):
        if "access_token" not in credentials:
            raise AuthError("Missing access token")
        
        token_data = self.token_manager.validate_access_token(credentials.access_token)
        if not token_data:
            raise AuthError("Invalid token")
        
        return {"user_id": token_data.user_id, "roles": token_data.roles}

class BasicAuthStrategy:
    function authenticate(credentials):
        if "username" not in credentials or "password" not in credentials:
            raise AuthError("Missing username or password")
        
        return self.auth_manager.login(credentials.username, credentials.password)

// Usage Examples
function example_authentication():
    # Initialize components
    user_store = UserStore()
    token_manager = TokenManager("your-secret-key")
    password_manager = PasswordManager()
    auth_manager = AuthManager(user_store, token_manager, password_manager)
    
    # Register strategies
    auth_manager.register_strategy("jwt", JWTStrategy())
    auth_manager.register_strategy("basic", BasicAuthStrategy())
    
    # User registration
    user = user_store.create_user({
        "username": "john_doe",
        "email": "john@example.com",
        "password": "secure_password_123"
    })
    
    # Login
    login_result = auth_manager.login("john_doe", "secure_password_123")
    
    # API request with authentication
    request = create_request()
    request.headers["Authorization"] = f"Bearer {login_result.access_token}"
    
    authenticated_request = AuthMiddleware(auth_manager, token_manager).authenticate_request(request)
    
    print(f"Authenticated user: {authenticated_request.user.username}")

function api_endpoints_example():
    # Login endpoint
    def login(request):
        try:
            credentials = request.json
            result = auth_manager.login(credentials.username, credentials.password)
            return {"success": True, "data": result}
        except AuthError as e:
            return {"success": False, "error": e.message}
    
    # Protected endpoint
    def get_user_profile(request):
        try:
            authenticated_request = auth_middleware.authenticate_request(request)
            user = authenticated_request.user
            return {"success": True, "data": auth_manager.sanitize_user(user)}
        except AuthError as e:
            return {"success": False, "error": e.message}
    
    # Refresh token endpoint
    def refresh_token(request):
        try:
            refresh_token = request.json.get("refresh_token")
            result = auth_manager.refresh_token(refresh_token)
            return {"success": True, "data": result}
        except AuthError as e:
            return {"success": False, "error": e.message}
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```typescript
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { Request, Response, NextFunction } from 'express';

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  roles: string[];
  createdAt: Date;
  lastLogin?: Date;
}

interface TokenPayload {
  userId: string;
  username: string;
  email: string;
  roles: string[];
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}

class TokenManager {
  constructor(
    private secretKey: string,
    private accessTokenExpiry: number = 3600,
    private refreshTokenExpiry: number = 86400
  ) {}

  generateAccessToken(user: User): string {
    const payload: Omit<TokenPayload, 'iat' | 'exp'> = {
      userId: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      type: 'access'
    };

    return jwt.sign(payload, this.secretKey, {
      expiresIn: this.accessTokenExpiry
    });
  }

  generateRefreshToken(user: User): string {
    const payload = {
      userId: user.id,
      type: 'refresh'
    };

    return jwt.sign(payload, this.secretKey, {
      expiresIn: this.refreshTokenExpiry
    });
  }

  validateAccessToken(token: string): TokenPayload | null {
    try {
      const decoded = jwt.verify(token, this.secretKey) as TokenPayload;
      return decoded.type === 'access' ? decoded : null;
    } catch (error) {
      return null;
    }
  }

  validateRefreshToken(token: string): { userId: string } | null {
    try {
      const decoded = jwt.verify(token, this.secretKey) as any;
      return decoded.type === 'refresh' ? { userId: decoded.userId } : null;
    } catch (error) {
      return null;
    }
  }
}

class PasswordManager {
  private readonly saltRounds = 12;

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  generateStrongPassword(length: number = 16): string {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}

class AuthManager {
  constructor(
    private userStore: UserStore,
    private tokenManager: TokenManager,
    private passwordManager: PasswordManager
  ) {}

  async login(username: string, password: string) {
    const user = await this.userStore.findByUsername(username);
    if (!user) {
      throw new AuthError('Invalid credentials');
    }

    const isValid = await this.passwordManager.verify(password, user.passwordHash);
    if (!isValid) {
      throw new AuthError('Invalid credentials');
    }

    const accessToken = this.tokenManager.generateAccessToken(user);
    const refreshToken = this.tokenManager.generateRefreshToken(user);

    await this.userStore.updateLastLogin(user.id);

    return {
      accessToken,
      refreshToken,
      user: this.sanitizeUser(user),
      expiresIn: this.tokenManager['accessTokenExpiry']
    };
  }

  async refreshToken(refreshToken: string) {
    const tokenData = this.tokenManager.validateRefreshToken(refreshToken);
    if (!tokenData) {
      throw new AuthError('Invalid refresh token');
    }

    const user = await this.userStore.findById(tokenData.userId);
    if (!user) {
      throw new AuthError('User not found');
    }

    const newAccessToken = this.tokenManager.generateAccessToken(user);

    return {
      accessToken: newAccessToken,
      expiresIn: this.tokenManager['accessTokenExpiry']
    };
  }

  private sanitizeUser(user: User) {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    };
  }
}

// Express middleware
export const authenticateToken = (authManager: AuthManager) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing authorization header' });
      }

      const token = authHeader.split(' ')[1];
      const tokenData = authManager['tokenManager'].validateAccessToken(token);
      
      if (!tokenData) {
        return res.status(401).json({ error: 'Invalid or expired token' });
      }

      const user = await authManager['userStore'].findById(tokenData.userId);
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      req.user = user;
      req.userRoles = tokenData.roles;
      next();
    } catch (error) {
      res.status(401).json({ error: 'Authentication failed' });
    }
  };
};

// Usage in routes
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await authManager.login(username, password);
    res.json({ success: true, data: result });
  } catch (error) {
    res.status(401).json({ success: false, error: error.message });
  }
});

app.get('/api/profile', authenticateToken(authManager), (req, res) => {
  res.json({ success: true, data: req.user });
});
```

### Python
```python
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from functools import wraps

class TokenManager:
    def __init__(self, secret_key: str, access_expiry: int = 3600, refresh_expiry: int = 86400):
        self.secret_key = secret_key
        self.access_expiry = access_expiry
        self.refresh_expiry = refresh_expiry
        self.blacklisted_tokens = set()
    
    def generate_access_token(self, user: Dict[str, Any]) -> str:
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'roles': user['roles'],
            'type': 'access',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.access_expiry)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def generate_refresh_token(self, user: Dict[str, Any]) -> str:
        payload = {
            'user_id': user['id'],
            'type': 'refresh',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.refresh_expiry)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def validate_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            if token in self.blacklisted_tokens:
                return None
            
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload if payload.get('type') == 'access' else None
        except jwt.PyJWTError:
            return None
    
    def validate_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload if payload.get('type') == 'refresh' else None
        except jwt.PyJWTError:
            return None
    
    def blacklist_token(self, token: str):
        self.blacklisted_tokens.add(token)

class PasswordManager:
    def __init__(self, rounds: int = 12):
        self.rounds = rounds
    
    def hash(self, password: str) -> str:
        salt = bcrypt.gensalt(rounds=self.rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify(self, password: str, hashed: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_strong_password(self, length: int = 16) -> str:
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

class AuthManager:
    def __init__(self, user_store, token_manager: TokenManager, password_manager: PasswordManager):
        self.user_store = user_store
        self.token_manager = token_manager
        self.password_manager = password_manager
    
    async def login(self, username: str, password: str) -> Dict[str, Any]:
        user = await self.user_store.find_by_username(username)
        if not user:
            raise AuthError("Invalid credentials")
        
        if not self.password_manager.verify(password, user['password_hash']):
            raise AuthError("Invalid credentials")
        
        access_token = self.token_manager.generate_access_token(user)
        refresh_token = self.token_manager.generate_refresh_token(user)
        
        await self.user_store.update_last_login(user['id'])
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': self._sanitize_user(user),
            'expires_in': self.token_manager.access_expiry
        }
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        token_data = self.token_manager.validate_refresh_token(refresh_token)
        if not token_data:
            raise AuthError("Invalid refresh token")
        
        user = await self.user_store.find_by_id(token_data['user_id'])
        if not user:
            raise AuthError("User not found")
        
        new_access_token = self.token_manager.generate_access_token(user)
        
        return {
            'access_token': new_access_token,
            'expires_in': self.token_manager.access_expiry
        }
    
    def _sanitize_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'roles': user['roles'],
            'created_at': user['created_at'],
            'last_login': user.get('last_login')
        }

# Decorator for protected routes
def require_auth(auth_manager: AuthManager):
    def decorator(func):
        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return {'error': 'Missing authorization header'}, 401
            
            token = auth_header.split(' ')[1]
            token_data = auth_manager.token_manager.validate_access_token(token)
            
            if not token_data:
                return {'error': 'Invalid or expired token'}, 401
            
            user = await auth_manager.user_store.find_by_id(token_data['user_id'])
            if not user:
                return {'error': 'User not found'}, 401
            
            request.user = user
            request.user_roles = token_data['roles']
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# Flask example
@app.route('/auth/login', methods=['POST'])
async def login():
    try:
        data = await request.get_json()
        result = await auth_manager.login(data['username'], data['password'])
        return jsonify({'success': True, 'data': result})
    except AuthError as e:
        return jsonify({'success': False, 'error': str(e)}), 401

@app.route('/api/profile', methods=['GET'])
@require_auth(auth_manager)
async def get_profile(request):
    return jsonify({'success': True, 'data': request.user})
```

### Go
```go
package auth

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

type User struct {
    ID          string    `json:"id"`
    Username    string    `json:"username"`
    Email       string    `json:"email"`
    PasswordHash string   `json:"-"`
    Roles       []string  `json:"roles"`
    CreatedAt   time.Time `json:"created_at"`
    LastLogin   *time.Time `json:"last_login,omitempty"`
}

type TokenClaims struct {
    UserID   string   `json:"user_id"`
    Username string   `json:"username"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
    Type     string   `json:"type"`
    jwt.RegisteredClaims
}

type TokenManager struct {
    secretKey           []byte
    accessTokenExpiry   time.Duration
    refreshTokenExpiry  time.Duration
    blacklistedTokens   map[string]bool
}

func NewTokenManager(secretKey string, accessExpiry, refreshExpiry time.Duration) *TokenManager {
    return &TokenManager{
        secretKey:           []byte(secretKey),
        accessTokenExpiry:   accessExpiry,
        refreshTokenExpiry:  refreshExpiry,
        blacklistedTokens:   make(map[string]bool),
    }
}

func (tm *TokenManager) GenerateAccessToken(user *User) (string, error) {
    claims := TokenClaims{
        UserID:   user.ID,
        Username: user.Username,
        Email:    user.Email,
        Roles:    user.Roles,
        Type:     "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.accessTokenExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(tm.secretKey)
}

func (tm *TokenManager) GenerateRefreshToken(user *User) (string, error) {
    claims := TokenClaims{
        UserID: user.ID,
        Type:   "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.refreshTokenExpiry)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(tm.secretKey)
}

func (tm *TokenManager) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
    if tm.blacklistedTokens[tokenString] {
        return nil, fmt.Errorf("token is blacklisted")
    }
    
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return tm.secretKey, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    claims, ok := token.Claims.(*TokenClaims)
    if !ok || claims.Type != "access" {
        return nil, fmt.Errorf("invalid token type")
    }
    
    return claims, nil
}

func (tm *TokenManager) BlacklistToken(tokenString string) {
    tm.blacklistedTokens[tokenString] = true
}

type PasswordManager struct {
    cost int
}

func NewPasswordManager(cost int) *PasswordManager {
    return &PasswordManager{cost: cost}
}

func (pm *PasswordManager) Hash(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), pm.cost)
    return string(bytes), err
}

func (pm *PasswordManager) Verify(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func (pm *PasswordManager) GenerateStrongPassword(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    
    bytes := make([]byte, length)
    rand.Read(bytes)
    
    for i, b := range bytes {
        bytes[i] = charset[b%byte(len(charset))]
    }
    
    return string(bytes)
}

type AuthMiddleware struct {
    tokenManager *TokenManager
    userStore    UserStore
}

func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := am.tokenManager.ValidateAccessToken(tokenString)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        user, err := am.userStore.FindByID(claims.UserID)
        if err != nil {
            http.Error(w, "User not found", http.StatusUnauthorized)
            return
        }
        
        // Add user to request context
        ctx := context.WithValue(r.Context(), "user", user)
        ctx = context.WithValue(ctx, "userRoles", claims.Roles)
        
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Usage example
func main() {
    tokenManager := NewTokenManager("your-secret-key", time.Hour, time.Hour*24)
    passwordManager := NewPasswordManager(12)
    userStore := NewUserStore()
    authManager := NewAuthManager(userStore, tokenManager, passwordManager)
    
    mux := http.NewServeMux()
    authMiddleware := &AuthMiddleware{
        tokenManager: tokenManager,
        userStore:    userStore,
    }
    
    // Protected route
    mux.Handle("/api/profile", authMiddleware.Authenticate(http.HandlerFunc(getProfile)))
}
```

## Best Practices

### 1. Security
- Use strong password hashing (bcrypt, Argon2)
- Implement secure token generation and validation
- Use HTTPS for all authentication endpoints
- Implement rate limiting for authentication attempts
- Store secrets securely (environment variables, secret managers)

### 2. Token Management
- Set appropriate expiration times for tokens
- Implement token refresh mechanism
- Blacklist tokens on logout
- Use different secrets for access/refresh tokens
- Include minimal data in tokens

### 3. User Management
- Validate user input (email format, password strength)
- Implement account lockout after failed attempts
- Provide password reset functionality
- Log authentication events for security monitoring
- Implement role-based access control

### 4. Error Handling
- Use generic error messages for authentication failures
- Don't reveal whether username or password is incorrect
- Log detailed errors for debugging
- Implement proper HTTP status codes
- Provide clear API documentation

## Adaptation Checklist

- [ ] Choose JWT library for your technology stack
- [ ] Implement secure password hashing with bcrypt
- [ ] Create token management system with refresh tokens
- [ ] Set up authentication middleware for your framework
- [ ] Implement user registration and login endpoints
- [ ] Add role-based access control
- [ ] Set up token blacklisting for logout
- [ ] Add security monitoring and logging

## Common Pitfalls

1. **Weak password storage** - Always use proper hashing algorithms
2. **Token leakage** - Never log tokens or include them in URLs
3. **Missing HTTPS** - Always use TLS for authentication
4. **Long-lived tokens** - Use appropriate expiration times
5. **Information disclosure** - Use generic error messages

---

*Generic Authentication Pattern - Adapt to your technology stack*
