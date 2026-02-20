# Changelog

All notable changes to the Stalkerhek project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] - 2026-02-21

### Added
- **WebUI Authentication System** - Complete login/register/logout functionality
  - Session-based authentication with secure cookies
  - bcrypt password hashing for security
  - 7-day session persistence
  - Optional authentication via `STALKERHEK_DISABLE_AUTH=1`
  
- **Security Questions & Password Reset**
  - 5 preset security questions for account recovery
  - Password reset flow via `/forgot-password` and `/reset-password`
  - Case-insensitive answer matching
  
- **Local Network Bypass**
  - Automatic authentication bypass for LAN connections
  - Trusted subnets: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  - Toggle control in `/account` Security tab
  - Configurable via `STALKERHEK_TRUSTED_SUBNETS` environment variable
  
- **Account Management Page** (`/account`)
  - Tabbed interface: Password, Security, Users
  - Change password functionality
  - Add new users (when registration enabled)
  - Local network bypass toggle
  - Security status display
  
- **Responsive Design**
  - Mobile-optimized auth pages
  - Flexible viewport scaling with `clamp()` CSS
  - Touch-friendly button sizes (min 44px)
  - Collapsible navigation on small screens
  
- **User Registration Flow**
  - Initial admin creation on first run
  - Optional user registration when `STALKERHEK_ALLOW_REGISTER=1`
  - Security question setup during registration
  - Password confirmation validation

### Changed
- **Color Scheme Harmonization**
  - Auth pages now match main WebUI dark green theme
  - Primary accent changed from blue (#5b8def) to green (#2d7a4e)
  - Consistent CSS variables across all pages
  - Dark gradient backgrounds (#0a0f0a to #0d1410)
  
- **Password Requirements**
  - Reduced minimum length from 8 to 4 characters
  - Better suited for home/Docker environments
  - Still uses bcrypt hashing for security
  
- **URL Handling**
  - Improved portal URL normalization
  - Preserves user-specified endpoints (/portal.php vs /load.php)
  - Better error messages for URL validation

### Fixed
- **Redirect Loop Issue**
  - Fixed infinite redirect when no users exist
  - Proper initial setup flow to `/register`
  - Graceful handling of first-time access
  
- **Authentication Flow**
  - Correct session validation
  - Proper cookie handling with HttpOnly and SameSite
  - Secure token generation

### Security
- bcrypt password hashing with default cost
- Secure session cookies (HttpOnly, SameSite=Strict)
- Automatic session expiration after 7 days
- Trusted subnet verification for LAN bypass
- Security question-based password recovery

### Technical
- Added `golang.org/x/crypto` dependency for bcrypt
- Persistent user storage in `auth.json`
- Thread-safe user and session management
- Environment-based configuration

---

## [Previous Versions]

### Early Development
- Initial Stalkerhek middleware implementation
- HLS and Proxy streaming support
- Basic WebUI with profile management
- Portal authentication with MAC-based device ID
- Optional portal parameters (Model, Serial, DeviceID, etc.)
- Channel and genre filtering
- Runtime tuning settings

---

## Planned Features

- [ ] Email-based password reset
- [ ] Two-factor authentication (TOTP)
- [ ] User roles and permissions
- [ ] Audit logging for account actions
- [ ] Session management (view/kill active sessions)
- [ ] Account lockout after failed attempts
- [ ] Password strength indicator
- [ ] Automatic backup of auth data

---

## Contributing

When adding changes to this changelog:
1. Add entries under `[Unreleased]`
2. Categorize as Added, Changed, Deprecated, Removed, Fixed, or Security
3. Keep entries concise but descriptive
4. Reference issue numbers when applicable

---

**Note:** This changelog tracks significant user-facing changes. For detailed code-level changes, refer to the git commit history.
