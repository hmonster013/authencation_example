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

### 🔄 Planned Authentication Methods
- **JWT Authentication** - JSON Web Token based stateless authentication
- **OAuth Authentication** - Third-party login (Google, GitHub)
- **Token Authentication** - Simple API token-based auth

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
├── jwt_auth/                      # 🔄 JWT authentication (planned)
├── oauth_auth/                    # 🔄 OAuth authentication (planned)
├── token_auth/                    # 🔄 Token authentication (planned)
├── templates/
│   ├── base.html                  # Base template
│   ├── basic_auth/                # Basic auth templates
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   └── profile.html
│   └── cookie_auth/               # Cookie auth templates
│       ├── home.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── profile.html
│       └── settings.html
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

### Running Tests
```bash
# Test basic authentication
python manage.py test basic_auth

# Test cookie authentication
python manage.py test cookie_auth

# Test all authentication methods
python manage.py test basic_auth cookie_auth
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
- 🔄 **JWT Authentication**: In development
- 🔄 **OAuth Authentication**: Planned
- 🔄 **Token Authentication**: Planned

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-auth-method`)
3. Commit changes (`git commit -am 'Add new authentication method'`)
4. Push to branch (`git push origin feature/new-auth-method`)
5. Create Pull Request

## 📝 License

This project is for educational purposes and demonstration of Django authentication methods.

## 📞 Support

For questions or issues, please create an issue in the repository.
