# Django Authentication Methods Demo

A comprehensive Django project demonstrating different authentication methods including Basic Authentication, JWT, OAuth, Token-based, and Cookie-based authentication.

## 🚀 Features

### ✅ Basic Authentication (Completed)
- **Session-based authentication** using Django's built-in auth system
- **User registration and login** with proper form validation
- **CSRF protection** for secure form submissions
- **Protected dashboard and profile pages**
- **Authentication status API endpoint**
- **Responsive Bootstrap UI**

### ✅ Cookie Authentication (Completed)
- **Advanced cookie management** with security flags (HttpOnly, Secure, SameSite)
- **Remember me functionality** with flexible session expiry
- **Custom authentication tokens** for enhanced security
- **Cookie preferences management** with user settings
- **Real-time cookie status monitoring**
- **Educational cookie information** and management tools

### ✅ Token Authentication (Completed)
- **Enterprise-grade API token system** with multiple token types
- **Advanced security features** (IP whitelisting, usage limits, scoped permissions)
- **Comprehensive token management** with web interface and REST API
- **Usage analytics and monitoring** with detailed logs
- **Token refresh mechanism** for long-term integrations
- **Developer-friendly API** with clear documentation

### ✅ JWT Authentication (Completed)
- **Stateless authentication** with JSON Web Tokens
- **Advanced session management** with device tracking and security monitoring
- **Token blacklisting** for secure logout and revocation
- **Rate limiting** and brute force protection
- **Multi-device support** with comprehensive session analytics
- **Enterprise security features** with IP tracking and login attempt monitoring

### 🔄 Planned Authentication Methods
- **OAuth Authentication** - Third-party login (Google, GitHub)

## 📋 Requirements

- Python 3.8+
- Django 5.2+
- See `requirements.txt` for full dependencies

## 🛠️ Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd authencation_example
```

2. **Create virtual environment**
```bash
python -m venv myvenv
# Windows
myvenv\Scripts\activate
# Linux/Mac
source myvenv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run migrations**
```bash
python manage.py makemigrations
python manage.py migrate
```

5. **Create superuser (optional)**
```bash
python manage.py createsuperuser
```

6. **Run development server**
```bash
python manage.py runserver
```

7. **Access the application**
- Main page: http://127.0.0.1:8000/
- Basic Auth: http://127.0.0.1:8000/basic/
- Cookie Auth: http://127.0.0.1:8000/cookie/
- Token Auth: http://127.0.0.1:8000/token/
- JWT Auth: http://127.0.0.1:8000/jwt/
- Admin panel: http://127.0.0.1:8000/admin/

## 🔐 Basic Authentication Features

### Available Endpoints
- `/basic/` - Home page with authentication overview
- `/basic/login/` - User login
- `/basic/register/` - User registration
- `/basic/logout/` - User logout
- `/basic/dashboard/` - Protected dashboard (login required)
- `/basic/profile/` - User profile page (login required)
- `/basic/api/status/` - Authentication status API

### Key Implementation Details

#### Views (`basic_auth/views.py`)
- **`basic_login`**: Handles user authentication with CSRF protection
- **`basic_register`**: User registration with automatic login
- **`basic_logout`**: Secure logout with session cleanup
- **`basic_dashboard`**: Protected view requiring authentication
- **`basic_profile`**: User profile management
- **`auth_status`**: JSON API for checking authentication status

#### Security Features
- ✅ CSRF protection on all forms
- ✅ Login required decorators for protected views
- ✅ Proper error handling and user feedback
- ✅ Session-based authentication
- ✅ Secure password validation

#### Templates
- **Responsive Bootstrap design**
- **Form validation with error display**
- **Dynamic authentication status checking**
- **Educational content explaining how each method works**

## 🎯 Usage Examples

### Basic Authentication Flow

1. **Registration**
   - Visit `/basic/register/`
   - Fill in username and password
   - Automatic login after successful registration

2. **Login**
   - Visit `/basic/login/`
   - Enter credentials
   - Redirect to dashboard on success

3. **Protected Access**
   - Dashboard and profile require authentication
   - Automatic redirect to login if not authenticated

4. **API Status Check**
   - JavaScript function checks authentication status
   - Real-time updates on authentication state

## 🍪 Cookie Authentication Features

### Available Endpoints
- `/cookie/` - Home page with cookie authentication overview
- `/cookie/login/` - User login with "Remember me" option
- `/cookie/register/` - User registration with automatic cookie setup
- `/cookie/logout/` - User logout with proper cookie cleanup
- `/cookie/dashboard/` - Protected dashboard with cookie information
- `/cookie/profile/` - User profile with session data
- `/cookie/settings/` - Cookie management and preferences
- `/cookie/api/status/` - Cookie authentication status API

### Key Implementation Details

#### Advanced Cookie Features
- **Security Flags**: HttpOnly, Secure, SameSite protection
- **Flexible Expiry**: Session cookies vs long-term (30 days) with "Remember me"
- **Custom Tokens**: Generated authentication tokens for enhanced security
- **Preference Storage**: User preferences stored in secure cookies
- **Real-time Monitoring**: Live cookie status updates via JavaScript

#### Cookie Management
- **Settings Page**: Users can manage cookie preferences (theme, language)
- **Cookie Dashboard**: View all cookies with detailed information
- **Automatic Cleanup**: Proper cookie deletion on logout
- **Educational Content**: Information about how cookie authentication works

#### Security Implementation
- ✅ HttpOnly cookies prevent XSS attacks
- ✅ Secure flag ensures HTTPS-only transmission
- ✅ SameSite protection against CSRF attacks
- ✅ Custom authentication token generation
- ✅ Configurable session expiry based on user preference

## 🎫 JWT Authentication Features

### Available Endpoints
- `/jwt/` - Home page with JWT authentication overview
- `/jwt/login/` - User login with JWT session creation
- `/jwt/register/` - User registration with automatic JWT session
- `/jwt/logout/` - User logout with token blacklisting
- `/jwt/dashboard/` - Protected dashboard with session statistics
- `/jwt/profile/` - User profile with login analytics
- `/jwt/sessions/` - Comprehensive session management interface
- `/jwt/session/<uuid>/` - Detailed session view with activity logs
- `/jwt/api/login/` - API endpoint for JWT authentication
- `/jwt/api/logout/` - API endpoint for JWT logout with blacklisting
- `/jwt/api/user/` - API endpoint for user profile (requires JWT)
- `/jwt/api/sessions/` - API endpoint for session management
- `/jwt/api/token/` - DRF SimpleJWT token obtain endpoint
- `/jwt/api/token/refresh/` - DRF SimpleJWT token refresh endpoint
- `/jwt/api/status/` - JWT authentication status API

### Key Implementation Details

#### JWT Token Management
- **Access Tokens**: Short-lived (60 minutes) for API authentication
- **Refresh Tokens**: Medium-lived (7 days) with automatic rotation
- **Token Blacklisting**: Secure revocation of compromised tokens
- **Custom Claims**: Extended token information (session_id, IP address)

#### Advanced Security Features
- **Rate Limiting**: Prevent brute force attacks (5 attempts per 15 minutes)
- **Login Monitoring**: Comprehensive logging of all authentication attempts
- **Device Tracking**: Browser, OS, and device type identification
- **IP Monitoring**: Track login locations and detect suspicious activity
- **Session Management**: Multi-device session tracking and termination
- **Automatic Cleanup**: Scheduled removal of expired tokens and sessions

#### Session Analytics
- **Device Information**: Detailed browser and OS detection
- **Login History**: Complete audit trail of authentication attempts
- **Session Timeline**: Visual representation of session lifecycle
- **Security Monitoring**: Real-time alerts for suspicious activities
- **Multi-device Support**: Manage sessions across different devices

#### Developer Experience
- **RESTful API**: Clean and intuitive API endpoints
- **Comprehensive Documentation**: Clear examples and usage guides
- **Error Handling**: Detailed error messages and status codes
- **Test Interface**: Built-in API testing tools in web interface
- **Management Commands**: CLI tools for token cleanup and maintenance

## 🎟️ Token Authentication Features

### Available Endpoints
- `/token/` - Home page with token authentication overview
- `/token/login/` - User login with optional API token creation
- `/token/register/` - User registration with automatic API key generation
- `/token/logout/` - User logout with session cleanup
- `/token/dashboard/` - Protected dashboard with token statistics
- `/token/profile/` - User profile with usage analytics
- `/token/management/` - Comprehensive token management interface
- `/token/token/<id>/` - Detailed token view with usage logs
- `/token/api/user/` - API endpoint for user profile (requires token)
- `/token/api/token/info/` - API endpoint for token information
- `/token/api/token/create/` - API endpoint to create new tokens
- `/token/api/token/refresh/` - API endpoint to refresh tokens
- `/token/api/token/revoke/` - API endpoint to revoke tokens
- `/token/api/status/` - Token authentication status API

### Key Implementation Details

#### Token Types
- **Access Tokens**: Short-lived (24 hours) for temporary access
- **Refresh Tokens**: Medium-lived (30 days) for generating new access tokens
- **API Keys**: Long-lived (1 year) for permanent integrations

#### Advanced Security Features
- **Secure Token Generation**: Cryptographically secure using SHA256
- **IP Whitelisting**: Restrict token usage to specific IP addresses
- **Usage Limits**: Set maximum number of uses per token
- **Scoped Permissions**: Fine-grained access control (read, write, admin, delete)
- **Usage Tracking**: Comprehensive logging of all token usage
- **Automatic Expiry**: Time-based token invalidation

#### Token Management
- **Web Interface**: User-friendly token management dashboard
- **REST API**: Programmatic token management via API
- **Usage Analytics**: Detailed statistics and usage patterns
- **Token Refresh**: Seamless token renewal for long-term integrations
- **Bulk Operations**: Extend, revoke, or manage multiple tokens

#### Developer Experience
- **API Documentation**: Clear endpoint documentation with examples
- **Test Interface**: Built-in API testing tools in web interface
- **Error Handling**: Comprehensive error messages and status codes
- **Masked Display**: Secure token display for UI safety

## 📁 Project Structure

```
authencation_example/
├── authencation_example/          # Main project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── basic_auth/                    # ✅ Basic authentication app
│   ├── views.py                   # Authentication views
│   ├── urls.py                    # URL routing
│   └── migrations/
├── cookie_auth/                   # ✅ Cookie authentication app
│   ├── views.py                   # Advanced cookie views
│   ├── urls.py                    # Cookie URL routing
│   ├── tests.py                   # Cookie auth tests
│   └── migrations/
├── jwt_auth/                      # ✅ JWT authentication app
│   ├── views.py                   # JWT auth views and API endpoints
│   ├── models.py                  # JWTBlacklist, JWTUserSession, JWTLoginAttempt models
│   ├── urls.py                    # JWT URL routing
│   ├── admin.py                   # Django admin configuration
│   ├── tests.py                   # JWT auth tests
│   ├── management/                # Management commands
│   │   └── commands/
│   │       └── cleanup_jwt_tokens.py  # Token cleanup command
│   └── migrations/
├── oauth_auth/                    # 🔄 OAuth authentication (planned)
├── token_auth/                    # ✅ Token authentication app
│   ├── views.py                   # Token auth views and API endpoints
│   ├── models.py                  # APIToken and TokenUsageLog models
│   ├── urls.py                    # Token URL routing
│   ├── tests.py                   # Token auth tests
│   └── migrations/
├── templates/
│   ├── base.html                  # Base template
│   ├── basic_auth/                # Basic auth templates
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   └── profile.html
│   ├── cookie_auth/               # Cookie auth templates
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── profile.html
│   │   └── settings.html
│   ├── token_auth/                # Token auth templates
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── profile.html
│   │   ├── management.html
│   │   └── token_detail.html
│   └── jwt_auth/                  # JWT auth templates
│       ├── home.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── profile.html
│       ├── session_management.html
│       └── session_detail.html
├── static/                        # Static files
├── requirements.txt               # Dependencies
└── manage.py
```

## 🧪 Testing

### Manual Testing Checklist for Basic Auth
- [ ] User can register new account
- [ ] User can login with valid credentials
- [ ] Invalid credentials show error message
- [ ] Protected pages redirect to login
- [ ] User can access dashboard after login
- [ ] User can view profile page
- [ ] Logout works correctly
- [ ] Authentication status API returns correct data
- [ ] CSRF protection is working
- [ ] Form validation displays errors properly

### Manual Testing Checklist for Cookie Auth
- [ ] User can register and cookies are set properly
- [ ] Login with "Remember me" creates long-term cookies
- [ ] Login without "Remember me" creates session cookies
- [ ] Cookies have proper security flags (HttpOnly, Secure, SameSite)
- [ ] Dashboard shows detailed cookie information
- [ ] Cookie settings page allows preference management
- [ ] Logout properly clears all authentication cookies
- [ ] Cookie status API returns accurate information
- [ ] Real-time cookie monitoring works correctly
- [ ] User preferences are saved and retrieved from cookies

### Manual Testing Checklist for JWT Auth
- [ ] User can register and receive JWT session automatically
- [ ] Login with "Create session" option generates JWT tokens
- [ ] Dashboard displays session statistics and device information
- [ ] Session management page shows all active sessions
- [ ] Session detail page shows comprehensive activity logs
- [ ] API endpoints work with proper Bearer token authentication
- [ ] Token blacklisting immediately invalidates access
- [ ] Rate limiting prevents brute force attacks (5 attempts/15min)
- [ ] Device tracking captures browser and OS information
- [ ] Multi-device sessions can be managed independently
- [ ] Session termination works for individual and all sessions
- [ ] Login attempt monitoring logs all authentication events

### Manual Testing Checklist for Token Auth
- [ ] User can register and receive initial API key
- [ ] Login with "Create token" option generates new token
- [ ] Dashboard displays token statistics correctly
- [ ] Token management page allows creating different token types
- [ ] Token detail page shows usage logs and statistics
- [ ] API endpoints work with proper Authorization header
- [ ] Token scopes are enforced correctly
- [ ] Token expiry and usage limits work as expected
- [ ] IP whitelisting restricts access properly
- [ ] Token refresh mechanism works for refresh tokens
- [ ] Token revocation immediately invalidates access
- [ ] Usage logging captures all API calls accurately

### Running Tests
```bash
# Test basic authentication
python manage.py test basic_auth

# Test cookie authentication
python manage.py test cookie_auth

# Test token authentication
python manage.py test token_auth

# Test JWT authentication
python manage.py test jwt_auth

# Test all authentication methods
python manage.py test basic_auth cookie_auth token_auth jwt_auth
```

## 🔧 Configuration

### Settings (`authencation_example/settings.py`)
Key configurations for authentication:
- `INSTALLED_APPS`: Includes all auth-related apps
- `MIDDLEWARE`: CSRF and session middleware
- `LOGIN_URL`: Default login redirect
- `LOGIN_REDIRECT_URL`: Post-login redirect

## 🚧 Development Status

- ✅ **Basic Authentication**: Complete with full functionality
- ✅ **Cookie Authentication**: Complete with advanced cookie management
- ✅ **Token Authentication**: Complete with enterprise-grade features
- ✅ **JWT Authentication**: Complete with advanced session management
- 🔄 **OAuth Authentication**: Planned

## 🎯 Usage Examples

### Token Authentication API Usage

#### Creating a Token via API
```bash
curl -X POST http://localhost:8000/token/api/token/create/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password",
    "token_name": "My API Token",
    "token_type": "api_key",
    "scopes": ["read", "write"]
  }'
```

#### Using Token for API Calls
```bash
# Get user profile
curl -H "Authorization: Token YOUR_TOKEN_HERE" \
     http://localhost:8000/token/api/user/

# Get token information
curl -H "Authorization: Token YOUR_TOKEN_HERE" \
     http://localhost:8000/token/api/token/info/
```

#### Token Management
```bash
# Refresh token (requires refresh token)
curl -X POST http://localhost:8000/token/api/token/refresh/ \
  -H "Authorization: Token YOUR_REFRESH_TOKEN"

# Revoke token
curl -X POST http://localhost:8000/token/api/token/revoke/ \
  -H "Authorization: Token YOUR_TOKEN_HERE"
```

### Token Authentication Web Flow

1. **Registration**
   - Visit `/token/register/`
   - Automatic API key generation upon registration
   - Immediate access to token management dashboard

2. **Login with Token Creation**
   - Visit `/token/login/`
   - Check "Create API token on login" for immediate token
   - Redirect to dashboard with new token information

3. **Token Management**
   - Dashboard: `/token/dashboard/` - Overview and statistics
   - Management: `/token/management/` - Create and manage tokens
   - Detail View: `/token/token/<id>/` - Detailed token information and logs

4. **API Integration**
   - Copy token from web interface
   - Use in Authorization header: `Authorization: Token YOUR_TOKEN`
   - Monitor usage via web dashboard

### JWT Authentication API Usage

#### Login to Get JWT Tokens
```bash
curl -X POST http://localhost:8000/jwt/api/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

#### Using JWT Token for API Calls
```bash
# Get user profile
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/jwt/api/user/

# Get user sessions
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     http://localhost:8000/jwt/api/sessions/
```

#### Token Refresh
```bash
# Refresh access token using refresh token
curl -X POST http://localhost:8000/jwt/api/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh": "YOUR_REFRESH_TOKEN"
  }'
```

#### Session Management
```bash
# Terminate specific session
curl -X POST http://localhost:8000/jwt/api/sessions/terminate/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "SESSION_UUID"
  }'

# Terminate all sessions
curl -X POST http://localhost:8000/jwt/api/sessions/terminate-all/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Logout (blacklist current token)
curl -X POST http://localhost:8000/jwt/api/logout/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### JWT Authentication Web Flow

1. **Registration**
   - Visit `/jwt/register/`
   - Automatic JWT session creation upon registration
   - Immediate access to session management dashboard

2. **Login with JWT Session**
   - Visit `/jwt/login/`
   - Check "Create JWT session on login" for token generation
   - Redirect to dashboard with session information

3. **Session Management**
   - Dashboard: `/jwt/dashboard/` - Overview and session statistics
   - Sessions: `/jwt/sessions/` - Manage all active sessions
   - Detail View: `/jwt/session/<uuid>/` - Detailed session information

4. **API Integration**
   - Use access token in Authorization header: `Authorization: Bearer YOUR_TOKEN`
   - Refresh tokens automatically when access token expires
   - Monitor sessions and device activity via web dashboard

## 📚 API Documentation

### Token Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/token/api/user/` | Get user profile | ✅ Token |
| `GET` | `/token/api/token/info/` | Get current token info | ✅ Token |
| `POST` | `/token/api/token/create/` | Create new token | ❌ Username/Password |
| `POST` | `/token/api/token/refresh/` | Refresh access token | ✅ Refresh Token |
| `POST` | `/token/api/token/revoke/` | Revoke current token | ✅ Token |
| `GET` | `/token/api/status/` | Check auth status | ❌ None |

### Token Authentication Header Format
```
Authorization: Token YOUR_TOKEN_HERE
```

### JWT Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/jwt/api/login/` | JWT login | ❌ Username/Password |
| `POST` | `/jwt/api/logout/` | JWT logout with blacklisting | ✅ JWT Token |
| `GET` | `/jwt/api/user/` | Get user profile | ✅ JWT Token |
| `GET` | `/jwt/api/sessions/` | Get user sessions | ✅ JWT Token |
| `POST` | `/jwt/api/sessions/terminate/` | Terminate specific session | ✅ JWT Token |
| `POST` | `/jwt/api/sessions/terminate-all/` | Terminate all sessions | ✅ JWT Token |
| `POST` | `/jwt/api/token/` | Obtain JWT tokens | ❌ Username/Password |
| `POST` | `/jwt/api/token/refresh/` | Refresh access token | ❌ Refresh Token |
| `GET` | `/jwt/api/status/` | Check JWT auth status | ❌ None |

### JWT Authentication Header Format
```
Authorization: Bearer YOUR_JWT_TOKEN
```

### Response Formats

#### JWT Login Response
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "token_type": "Bearer",
  "expires_in": 3600,
  "message": "Login successful"
}
```

#### JWT User Profile Response
```json
{
  "user_id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "date_joined": "2024-01-01T00:00:00Z",
  "session_info": {
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "created_at": "2024-01-01T10:00:00Z",
    "last_activity": "2024-01-01T10:30:00Z",
    "expires_at": "2024-01-08T10:00:00Z",
    "ip_address": "192.168.1.100",
    "device_info": {
      "browser": "Chrome 120.0.0.0",
      "os": "Windows 10",
      "is_mobile": false
    }
  },
  "active_sessions": 3
}
```

#### Token Authentication User Profile Response
```json
{
  "user_id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "date_joined": "2024-01-01T00:00:00Z",
  "token_info": {
    "name": "My API Token",
    "type": "api_key",
    "scopes": ["read", "write"],
    "expires_at": "2025-01-01T00:00:00Z",
    "usage_count": 42
  }
}
```

#### Error Response
```json
{
  "error": "Invalid credentials",
  "detail": "Token authentication failed"
}
```

## 🔒 Security Best Practices

### Token Security
- **Never expose tokens in client-side code** or version control
- **Use HTTPS in production** to protect tokens in transit
- **Implement token rotation** for long-lived integrations
- **Monitor token usage** for suspicious activity
- **Use appropriate scopes** - grant minimal necessary permissions
- **Set reasonable expiry times** based on use case

### IP Whitelisting
- Configure IP restrictions for sensitive tokens
- Use for server-to-server integrations
- Regularly review and update IP whitelist

### Usage Monitoring
- Review token usage logs regularly
- Set up alerts for unusual usage patterns
- Monitor failed authentication attempts
- Track token usage across different endpoints

### Token Types Best Practices
- **Access Tokens**: Use for short-term, user-facing applications
- **Refresh Tokens**: Use for mobile apps and SPAs that need long-term access
- **API Keys**: Use for server-to-server integrations and permanent access

### JWT Security Best Practices
- **Token Storage**: Store JWT tokens securely (httpOnly cookies for web, secure storage for mobile)
- **Token Rotation**: Implement refresh token rotation for enhanced security
- **Session Management**: Monitor and manage active sessions across devices
- **Blacklisting**: Implement token blacklisting for immediate revocation
- **Rate Limiting**: Protect against brute force attacks with login attempt limits
- **Device Tracking**: Monitor login devices and locations for suspicious activity

### JWT vs Token Authentication
- **JWT**: Stateless, self-contained, ideal for microservices and mobile apps
- **Token Auth**: Stateful, server-side validation, better for traditional web apps
- **Use JWT when**: Building APIs, microservices, mobile apps, or need stateless auth
- **Use Token Auth when**: Building traditional web apps or need fine-grained control

## 🛠️ Management Commands

### JWT Token Cleanup
```bash
# Clean up expired JWT tokens and sessions (dry run)
python manage.py cleanup_jwt_tokens --dry-run

# Clean up expired tokens and sessions
python manage.py cleanup_jwt_tokens

# Clean up tokens and login attempts older than 60 days
python manage.py cleanup_jwt_tokens --days 60
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-auth-method`)
3. Commit changes (`git commit -am 'Add new authentication method'`)
4. Push to branch (`git push origin feature/new-auth-method`)
5. Create Pull Request

### Development Guidelines
- Follow Django best practices
- Add comprehensive tests for new features
- Update documentation for any new endpoints
- Ensure security considerations are addressed
- Add proper error handling and validation

## 🏆 Features Comparison

| Feature | Basic Auth | Cookie Auth | Token Auth | JWT Auth | OAuth |
|---------|------------|-------------|------------|----------|-------|
| **Session Management** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Stateless** | ❌ | ❌ | ✅ | ✅ | ❌ |
| **API Friendly** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Mobile Apps** | ❌ | ⚠️ | ✅ | ✅ | ✅ |
| **Third-party Integration** | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Scalability** | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ |
| **Security Features** | ⚠️ | ✅ | ✅ | ✅ | ✅ |
| **Ease of Implementation** | ✅ | ✅ | ⚠️ | ⚠️ | ❌ |

**Legend**: ✅ Excellent | ⚠️ Good | ❌ Not Suitable

## 📝 License

This project is for educational purposes and demonstration of Django authentication methods.

## 📞 Support

For questions or issues, please create an issue in the repository.

---

**🎯 Project Status**: 4/5 authentication methods completed
- ✅ Basic Authentication (Session-based)
- ✅ Cookie Authentication (Advanced cookie management)
- ✅ Token Authentication (Enterprise-grade API tokens)
- ✅ JWT Authentication (Stateless with advanced session management)
- 🔄 OAuth Authentication (Planned)
