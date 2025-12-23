# Two-Factor Authentication (TOTP) Implementation

## Overview

This implementation adds comprehensive two-factor authentication support to the CFMS server using Time-based One-Time Passwords (TOTP). The system allows users to set up, validate, and cancel 2FA, providing enhanced security for user accounts.

## Features

### 1. TOTP Support
- Industry-standard TOTP implementation using the `pyotp` library
- Compatible with popular authenticator apps (Google Authenticator, Authy, Microsoft Authenticator, etc.)
- QR code provisioning URI generation for easy setup

### 2. Backup Codes
- 10 single-use backup codes generated during setup
- Backup codes are hashed using SHA-256 before storage
- Used codes are automatically removed from the database

### 3. Secure Workflow
- Password verification required for cancellation
- TOTP must be validated before enabling
- Tokens verified with 1-window tolerance (90 seconds total validity)

## API Endpoints

### Setup 2FA
**Endpoint:** `setup_2fa`  
**Authentication Required:** Yes  
**Request:**
```json
{
  "action": "setup_2fa",
  "username": "user123",
  "token": "jwt_token",
  "data": {}
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "message": "Two-factor authentication setup initiated...",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "provisioning_uri": "otpauth://totp/CFMS:user123?secret=JBSWY3DPEHPK3PXP&issuer=CFMS",
    "backup_codes": [
      "a1b2c3d4",
      "e5f6g7h8",
      ...
    ]
  }
}
```

### Validate 2FA
**Endpoint:** `validate_2fa`  
**Authentication Required:** Yes  
**Request:**
```json
{
  "action": "validate_2fa",
  "username": "user123",
  "token": "jwt_token",
  "data": {
    "token": "123456"
  }
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "message": "Two-factor authentication enabled successfully",
  "data": {
    "totp_enabled": true
  }
}
```

### Get 2FA Status
**Endpoint:** `get_2fa_status`  
**Authentication Required:** Yes  
**Request:**
```json
{
  "action": "get_2fa_status",
  "username": "user123",
  "token": "jwt_token",
  "data": {}
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "message": "Two-factor authentication status",
  "data": {
    "totp_enabled": true,
    "backup_codes_count": 8
  }
}
```

### Cancel 2FA
**Endpoint:** `cancel_2fa`  
**Authentication Required:** Yes  
**Request:**
```json
{
  "action": "cancel_2fa",
  "username": "user123",
  "token": "jwt_token",
  "data": {
    "password": "user_password"
  }
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "message": "Two-factor authentication disabled successfully",
  "data": {
    "totp_enabled": false
  }
}
```

### Login with 2FA (Step 1)
**Endpoint:** `login`  
**Authentication Required:** No  
**Request:**
```json
{
  "action": "login",
  "data": {
    "username": "user123",
    "password": "user_password"
  }
}
```

**Response (202 Accepted):**
```json
{
  "code": 202,
  "message": "Two-factor authentication required",
  "data": {
    "requires_2fa": true,
    "username": "user123"
  }
}
```

### Verify 2FA Login (Step 2)
**Endpoint:** `verify_2fa`  
**Authentication Required:** No  
**Request:**
```json
{
  "action": "verify_2fa",
  "data": {
    "username": "user123",
    "token": "123456"
  }
}
```

**Response (200 OK):**
```json
{
  "code": 200,
  "message": "Two-factor authentication successful",
  "data": {
    "token": "jwt_token",
    "exp": 1234567890,
    "nickname": "User Name",
    "avatar_id": "avatar123",
    "permissions": ["read", "write"],
    "groups": ["users"]
  }
}
```

## Database Schema Changes

The following fields were added to the `users` table:

| Column | Type | Description |
|--------|------|-------------|
| `totp_secret` | VARCHAR(32) | Base32-encoded TOTP secret |
| `totp_enabled` | BOOLEAN | Whether 2FA is enabled |
| `totp_backup_codes` | TEXT | JSON array of hashed backup codes |

## Security Considerations

1. **Backup Code Security**: Backup codes are hashed using SHA-256 before storage. The plain-text codes are only shown once during setup.

2. **Password Protection**: Canceling 2FA requires password verification to prevent unauthorized disabling.

3. **Token Validation**: TOTP tokens are validated with a 1-window tolerance, allowing for slight clock drift while maintaining security.

4. **Backup Code Consumption**: Used backup codes are immediately removed from the database to prevent reuse.

5. **No Security Vulnerabilities**: CodeQL security scanning found no vulnerabilities in the implementation.

## Client Integration Example

```python
import pyotp

# 1. Setup 2FA
response = await client.setup_2fa()
secret = response["data"]["secret"]
provisioning_uri = response["data"]["provisioning_uri"]
backup_codes = response["data"]["backup_codes"]

# Display QR code using provisioning_uri
# Or display secret for manual entry

# 2. Validate with TOTP token
totp = pyotp.TOTP(secret)
token = totp.now()
response = await client.validate_2fa(token)

# 3. Login with 2FA
login_response = await client.login("username", "password")
if login_response["code"] == 202:
    # 2FA required
    token = totp.now()  # Get fresh token from authenticator
    auth_response = await client.verify_2fa_login("username", token)
    # Use auth_response["data"]["token"] for authenticated requests

# 4. Cancel 2FA
response = await client.cancel_2fa("password")
```

## Testing

Comprehensive test suite included in `tests/test_two_factor.py`:
- Setup 2FA with valid credentials
- Validate with valid/invalid tokens
- Cancel with valid/invalid passwords
- Login flow with 2FA enabled
- Backup code verification
- Error handling for various edge cases

## Dependencies

- `pyotp>=2.9.0`: TOTP implementation
- All existing CFMS dependencies maintained

## Backward Compatibility

This implementation is fully backward compatible:
- Users without 2FA enabled continue to use the standard login flow
- Existing authentication tokens remain valid
- No breaking changes to existing APIs
