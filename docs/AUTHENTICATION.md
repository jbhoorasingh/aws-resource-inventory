# Authentication and Authorization Guide

This guide covers the authentication and authorization system implemented in AWS Resource Inventory.

## Table of Contents

1. [Overview](#overview)
2. [Initial Setup](#initial-setup)
3. [User Management](#user-management)
4. [Permission Levels](#permission-levels)
5. [Authentication Methods](#authentication-methods)
6. [API Token Usage](#api-token-usage)
7. [EDL Token Usage](#edl-token-usage)
8. [Testing](#testing)

## Overview

AWS Resource Inventory implements a comprehensive authentication and authorization system with:

- **User Authentication**: Login/logout functionality for web UI access
- **Permission-based Authorization**: Role-based access control for AWS polling operations
- **Dual Token System**:
  - EDL API tokens for External Dynamic List endpoints (query parameter-based)
  - REST API tokens for programmatic access (header-based)
- **Automatic Token Generation**: Tokens are auto-generated for all users
- **Token Regeneration**: Users can regenerate their tokens at any time

## Initial Setup

### 1. Run Migrations

After cloning the repository, ensure all authentication-related migrations are applied:

```bash
# Apply all migrations including UserProfile and authtoken
poetry run python manage.py migrate
```

This creates:
- User authentication tables
- UserProfile model with EDL API tokens
- DRF authtoken table for REST API tokens

### 2. Create Initial Superuser

Create a superuser account with full administrative access:

```bash
poetry run python manage.py createsuperuser
```

You'll be prompted for:
- Username
- Email (optional)
- Password

**Superusers have all permissions automatically**, including:
- Access to Django admin panel (`/admin/`)
- Ability to poll AWS accounts
- Full API access

### 3. Access the Application

Start the development server:

```bash
poetry run python manage.py runserver
```

Navigate to `http://localhost:8000/` and log in with your superuser credentials.

## User Management

### Creating Regular Users

#### Option 1: Django Admin Panel (Recommended)

1. Log in to admin panel: `http://localhost:8000/admin/`
2. Navigate to **Users** under **Authentication and Authorization**
3. Click **Add User**
4. Set username and password
5. Click **Save**

The system automatically creates:
- UserProfile with unique EDL API token
- DRF auth token for REST API access

#### Option 2: Django Shell

```bash
poetry run python manage.py shell
```

```python
from django.contrib.auth.models import User

# Create a regular user
user = User.objects.create_user(
    username='alice',
    email='alice@example.com',
    password='secure_password_here'
)

# User profile and tokens are auto-created via signals
print(f"EDL Token: {user.profile.api_token}")
print(f"REST API Token: {user.auth_token.key}")
```

#### Option 3: Management Command

```bash
# Create user via shell one-liner
poetry run python manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_user('bob', 'bob@example.com', 'password123')"
```

### Granting Permissions

Use the `assign_poll_permission` management command to grant or revoke the `can_poll_accounts` permission:

```bash
# Grant permission to single user
poetry run python manage.py assign_poll_permission alice

# Grant permission to multiple users
poetry run python manage.py assign_poll_permission alice bob charlie

# Remove permission from user(s)
poetry run python manage.py assign_poll_permission alice --remove
```

**Output:**
```
✓ alice: Granted can_poll_accounts permission
✓ bob: Granted can_poll_accounts permission
✓ charlie: Granted can_poll_accounts permission

Done!
```

## Permission Levels

The application has three permission levels:

### 1. Superuser (is_superuser=True)

**Capabilities:**
- Full access to Django admin panel
- Can poll AWS accounts via web UI
- Can perform bulk polling
- Full REST API access
- Can manage users and permissions

**Badge in Profile:** Purple "Superuser" badge

### 2. Can Poll Accounts (resources.can_poll_accounts)

**Capabilities:**
- Can poll AWS accounts via web UI
- Can perform bulk polling
- Full REST API access
- Cannot access Django admin panel (unless also is_staff=True)

**Badge in Profile:** Blue "Can Poll Accounts" badge

**UI Indicators:**
- Sees "Poll Single Account" and "Bulk Poll Accounts" buttons on accounts page
- Can click "Poll" action button on individual accounts

### 3. Read-Only (Regular User)

**Capabilities:**
- Can view all resources (accounts, VPCs, subnets, ENIs, security groups, EC2 instances)
- Can access REST API for read operations
- Can use EDL endpoints
- Cannot poll accounts or modify data

**Badge in Profile:** Gray "Read-Only" badge

**UI Indicators:**
- Sees "Read-only access" message on accounts page
- Poll buttons are replaced with lock icons
- Cannot trigger AWS resource discovery

## Authentication Methods

### 1. Web UI Authentication (Session-based)

Users log in via the web interface at `/login/`:

```
URL: http://localhost:8000/login/
Method: POST
Fields:
  - username
  - password
```

**After successful login:**
- User is redirected to `/accounts/` (or the `next` parameter if provided)
- Session cookie is set for subsequent requests
- All frontend views require authentication via `@login_required` decorator

**Logout:**
```
URL: http://localhost:8000/logout/
Redirects to: /login/
```

### 2. REST API Authentication (Token-based)

The REST API (`/api/*`) supports two authentication methods:

#### Session Authentication (Browser-based)

If you're logged into the web UI, you can access the API directly in your browser:

```
http://localhost:8000/api/enis/
```

#### Token Authentication (Programmatic)

For scripts and applications, use the DRF auth token:

**Obtaining a Token:**

```bash
# Method 1: Via API endpoint
curl -X POST http://localhost:8000/api/auth/token/ \
  -d "username=alice&password=secure_password"

# Response:
{"token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"}
```

**Method 2: Via User Profile**

1. Log in to web UI
2. Navigate to Profile (`/profile/`)
3. Copy the REST API Token displayed

**Using the Token:**

Include the token in the `Authorization` header:

```bash
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
  http://localhost:8000/api/enis/
```

**All API endpoints require authentication.** Requests without valid authentication receive `403 Forbidden`.

## API Token Usage

### REST API Token (DRF Token)

**Purpose:** Programmatic access to REST API endpoints (`/api/*`)

**Authentication Method:** Header-based

**Format:**
```
Authorization: Token YOUR_TOKEN_HERE
```

**Example Usage:**

```bash
# List all ENIs
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
  http://localhost:8000/api/enis/

# Get ENI by IP address
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
  "http://localhost:8000/api/enis/by_ip/?ip=10.0.1.10"

# Filter VPCs by region
curl -H "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b" \
  "http://localhost:8000/api/vpcs/?region=us-east-1"
```

**Python Example:**

```python
import requests

TOKEN = "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
BASE_URL = "http://localhost:8000"

headers = {
    "Authorization": f"Token {TOKEN}"
}

# Get all accounts
response = requests.get(f"{BASE_URL}/api/accounts/", headers=headers)
accounts = response.json()

# Get ENI summary
response = requests.get(f"{BASE_URL}/api/enis/summary/", headers=headers)
summary = response.json()
print(f"Total ENIs: {summary['total_enis']}")
```

**Token Location:**
- User Profile page (`/profile/`) under "REST API Token"
- Or query via Django shell:
  ```python
  from django.contrib.auth.models import User
  from rest_framework.authtoken.models import Token

  user = User.objects.get(username='alice')
  token = Token.objects.get(user=user)
  print(token.key)
  ```

## EDL Token Usage

### EDL API Token (Custom Token)

**Purpose:** External Dynamic List endpoints for Palo Alto Networks firewall integration (`/edl/*`)

**Authentication Method:** Query parameter-based

**Format:**
```
?token=YOUR_TOKEN_HERE
```

**Example Usage:**

```bash
# Get all IPs for an account
curl "http://localhost:8000/edl/account/123456789012/?token=abc123def456"

# Get all IPs for a security group
curl "http://localhost:8000/edl/sg/sg-12345678/?token=abc123def456"

# Get ENIs filtered by tags
curl "http://localhost:8000/edl/enis/?token=abc123def456&Environment=PROD&Team=Platform"
```

**Output Format:**
```
10.0.1.10 # eni-0a1b2c3d4e5f, primary
10.0.1.11 # eni-0a1b2c3d4e5f, secondary
54.123.45.67 # eni-0a1b2c3d4e5f, primary
```

**Token Location:**
- User Profile page (`/profile/`) under "EDL API Token"
- EDL Summary page (`/edl/`) displays personalized URLs with your token
- Or query via Django shell:
  ```python
  from django.contrib.auth.models import User

  user = User.objects.get(username='alice')
  print(user.profile.api_token)
  ```

**Firewall Configuration:**

In Palo Alto Networks firewalls, configure External Dynamic Lists with URLs including your token:

```
Type: IP List
URL: http://your-server:8000/edl/account/123456789012/?token=YOUR_TOKEN
Refresh Interval: 5 minutes
```

## Token Regeneration

Users can regenerate their tokens if compromised or for security rotation.

### Regenerating EDL API Token

**Via Web UI:**

1. Log in to application
2. Navigate to Profile (`/profile/`)
3. Scroll to "EDL API Token" section
4. Click "Regenerate Token" button
5. Confirm the action (warning: invalidates all existing EDL URLs)
6. New token is displayed immediately

**Important:** After regenerating:
- All existing EDL URLs with the old token will stop working
- Update all firewall configurations with the new token
- The old token is permanently invalidated

**Via Django Shell:**

```python
from django.contrib.auth.models import User

user = User.objects.get(username='alice')
new_token = user.profile.regenerate_token()
print(f"New EDL token: {new_token}")
```

### Regenerating REST API Token

REST API tokens cannot currently be regenerated via the UI. To regenerate:

**Via Django Shell:**

```python
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

user = User.objects.get(username='alice')

# Delete old token and create new one
Token.objects.filter(user=user).delete()
new_token = Token.objects.create(user=user)
print(f"New REST API token: {new_token.key}")
```

**Via Django Admin:**

1. Navigate to `/admin/`
2. Go to **Auth Token** > **Tokens**
3. Find the user's token
4. Delete it
5. A new token is auto-created on next API access or via profile page

## Security Best Practices

### Token Security

1. **Never commit tokens to version control**
   - Keep tokens secret and rotate regularly
   - Use environment variables or secure vaults for automation

2. **Use HTTPS in production**
   - Tokens are transmitted in headers/URLs
   - Configure SSL/TLS certificates

3. **Limit token scope**
   - Grant `can_poll_accounts` permission only to trusted users
   - Use read-only accounts for monitoring/reporting

4. **Regular rotation**
   - Regenerate tokens periodically
   - Immediately regenerate if token is compromised

5. **Monitor access logs**
   - Review Django logs for suspicious activity
   - Track failed authentication attempts

### Password Security

1. **Enforce strong passwords**
   - Django's default validators require minimum complexity
   - Consider additional validators in production

2. **Use Django admin for user management**
   - Passwords are properly hashed (PBKDF2 SHA256)
   - Never store plain-text passwords

## Testing

The authentication system includes comprehensive test coverage:

### Running Tests

```bash
# Run all authentication tests
poetry run python manage.py test resources.tests.test_authentication \
  resources.tests.test_authorization \
  resources.tests.test_edl_authentication \
  resources.tests.test_api_authentication \
  resources.tests.test_management_commands

# Run specific test class
poetry run python manage.py test resources.tests.test_authentication.LoginViewTest

# Run with verbose output
poetry run python manage.py test resources.tests.test_authentication --verbosity=2
```

### Test Coverage

**Test Files:**

1. `resources/tests/test_authentication.py` - User authentication (login/logout/profile)
2. `resources/tests/test_authorization.py` - Permission-based access control
3. `resources/tests/test_edl_authentication.py` - EDL endpoint token authentication
4. `resources/tests/test_api_authentication.py` - REST API authentication (Session + Token)
5. `resources/tests/test_management_commands.py` - assign_poll_permission command

**What's Tested:**

- ✅ UserProfile auto-creation on User creation
- ✅ API token auto-generation
- ✅ Login with valid/invalid credentials
- ✅ Logout functionality
- ✅ Profile page displays user info and tokens
- ✅ Token regeneration
- ✅ Frontend view protection with @login_required
- ✅ Permission enforcement on poll endpoints
- ✅ EDL endpoint token validation
- ✅ REST API Session authentication
- ✅ REST API Token authentication
- ✅ Token obtain endpoint
- ✅ Permission-based UI element visibility
- ✅ Management command for permission assignment

### Manual Testing

**Test User Authentication:**

```bash
# 1. Create test user
poetry run python manage.py shell -c "from django.contrib.auth.models import User; User.objects.create_user('testuser', password='testpass')"

# 2. Visit http://localhost:8000/login/
# 3. Log in with testuser / testpass
# 4. Verify redirect to /accounts/
# 5. Check that poll buttons show lock icon (read-only)

# 6. Grant permission
poetry run python manage.py assign_poll_permission testuser

# 7. Refresh page - poll buttons should now be visible
```

**Test API Authentication:**

```bash
# 1. Get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/token/ \
  -d "username=testuser&password=testpass" | jq -r '.token')

# 2. Test authenticated request
curl -H "Authorization: Token $TOKEN" \
  http://localhost:8000/api/accounts/

# 3. Test unauthenticated request (should return 403)
curl http://localhost:8000/api/accounts/
```

**Test EDL Authentication:**

```bash
# 1. Get EDL token from profile or shell
EDL_TOKEN=$(poetry run python manage.py shell -c "from django.contrib.auth.models import User; u=User.objects.get(username='testuser'); print(u.profile.api_token)")

# 2. Test authenticated request
curl "http://localhost:8000/edl/account/123456789012/?token=$EDL_TOKEN"

# 3. Test unauthenticated request (should return 401)
curl "http://localhost:8000/edl/account/123456789012/"
```

## Troubleshooting

### "This field is required" on login

**Issue:** Login form shows validation errors

**Solution:** Ensure you're providing both username and password

### 403 Forbidden on API requests

**Issue:** API returns 403 even with token

**Possible causes:**
1. Invalid or expired token - regenerate token
2. Token not included in header - check `Authorization: Token XXX` format
3. User account is inactive - check `user.is_active=True`

### 401 Unauthorized on EDL requests

**Issue:** EDL endpoint returns 401

**Possible causes:**
1. Missing token parameter - add `?token=XXX` to URL
2. Invalid token - verify token from profile page
3. Token was regenerated - update URL with new token

### Permission denied on poll endpoint

**Issue:** User cannot poll accounts despite being logged in

**Solution:** Grant `can_poll_accounts` permission:

```bash
poetry run python manage.py assign_poll_permission username
```

### Tokens not auto-created for existing users

**Issue:** Users created before auth implementation don't have tokens

**Solution:** Tokens are auto-created on access. Visit profile page or trigger via shell:

```python
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

for user in User.objects.all():
    # Create DRF token if missing
    Token.objects.get_or_create(user=user)
    # UserProfile with EDL token created by signal
```

## Migration from Pre-Auth Version

If upgrading from a version without authentication:

### 1. Run Migrations

```bash
poetry run python manage.py migrate
```

### 2. Create Superuser

```bash
poetry run python manage.py createsuperuser
```

### 3. Create Profiles for Existing Users

```python
poetry run python manage.py shell
```

```python
from django.contrib.auth.models import User
from resources.models import UserProfile
from rest_framework.authtoken.models import Token

# Profiles and tokens are auto-created by signals
# But for safety, ensure they exist:
for user in User.objects.all():
    UserProfile.objects.get_or_create(user=user)
    Token.objects.get_or_create(user=user)
```

### 4. Grant Permissions

Grant polling permission to users who should be able to trigger AWS discovery:

```bash
poetry run python manage.py assign_poll_permission alice bob
```

### 5. Update EDL URLs

If you were using EDL endpoints without authentication:

1. Log in to each user's profile
2. Copy their EDL token
3. Update firewall configurations with URLs including `?token=XXX`

## Additional Resources

- [Django Authentication Documentation](https://docs.djangoproject.com/en/4.2/topics/auth/)
- [Django REST Framework Authentication](https://www.django-rest-framework.org/api-guide/authentication/)
- [Role Assumption Setup](ROLE_ASSUMPTION_SETUP.md)
- [Deployment Guide](DEPLOYMENT.md)
