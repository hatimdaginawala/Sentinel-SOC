# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active Security Updates |
| < 1.0   | ❌ End of Life |

> **Note**: SentinelSOC is currently in its initial release (v1.0.x). All versions within this major version receive security updates. Future major versions will be listed here as they are released.

---

## Reporting a Vulnerability

### How to Report

If you discover a security vulnerability in SentinelSOC, please report it responsibly by following these steps:

1. **Do NOT** create a public GitHub issue for the vulnerability.
2. **Email** the security team directly at: **hfdaginawala@gmail.com**
3. **Encrypt** your report using our PGP key (available upon request).

### What to Include in Your Report

To help us investigate and resolve the issue quickly, please provide:

| Information | Description |
|-------------|-------------|
| **Vulnerability Type** | e.g., SQL Injection, XSS, Authentication Bypass, Privilege Escalation |
| **Affected Component** | e.g., API endpoint `/api/v1/auth/login`, frontend page `/pages/dashboard.html` |
| **Steps to Reproduce** | Clear, step-by-step instructions to reproduce the vulnerability |
| **Impact** | What an attacker could achieve by exploiting this vulnerability |
| **Proof of Concept** | Code snippets, screenshots, or video demonstrations (redact sensitive data) |
| **Environment** | Browser, Node.js version, MongoDB version, operating system |

### Response Timeline

| Stage | Timeline |
|-------|----------|
| **Initial Acknowledgment** | Within 24 hours of submission |
| **Validation** | Within 3 business days |
| **Investigation & Fix** | Within 7-14 business days (depends on severity) |
| **Public Disclosure** | 30 days after fix is deployed (or after user notification) |

### What to Expect

- **Accepted**: We will work on a fix and notify you when it's resolved.
- **Declined**: We will explain why the issue is not considered a security vulnerability (e.g., already documented, out of scope, requires prior authentication).
- **Deferred**: We will address the issue in a future release if it's low severity.

### Responsible Disclosure Policy

We believe in responsible disclosure. We ask that you:

- Allow us reasonable time to investigate and fix the issue before disclosing it publicly.
- Do not exploit the vulnerability for malicious purposes.
- Keep the vulnerability confidential until we have addressed it.

---

## Security Best Practices for Deployment

### Production Environment

| Control | Recommendation |
|---------|----------------|
| **Secrets Management** | Use environment variables, never hardcode secrets |
| **HTTPS** | Always use TLS/SSL in production |
| **Database Access** | Restrict MongoDB to localhost or internal network |
| **Rate Limiting** | Enable rate limiting on all API endpoints |
| **JWT Secrets** | Use strong, cryptographically random secrets (32+ characters) |
| **CORS** | Restrict CORS origins to trusted domains only |
| **Input Validation** | Validate all user inputs on the backend |
| **Audit Logging** | Enable audit logging for all sensitive operations |

### Recommended Environment Variables

```env
# Strong JWT Secrets - Generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
JWT_SECRET=your-super-secret-jwt-key-min-64-characters
JWT_REFRESH_SECRET=your-refresh-secret-min-64-characters

# Security Settings
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
CORS_ORIGIN=https://your-domain.com

# Production Database
MONGODB_URI=mongodb://127.0.0.1:27017/sentinel_soc
```

---

## Security Controls Implementation

SentinelSOC implements the following security controls:

| Control | Implementation |
|---------|----------------|
| **Authentication** | JWT with refresh token rotation |
| **Password Security** | bcrypt hashing with configurable salt rounds (12+) |
| **Rate Limiting** | express-rate-limit on API endpoints |
| **Security Headers** | Helmet.js with CSP configuration |
| **CORS** | Configurable CORS policies |
| **Input Validation** | express-validator on all requests |
| **Data Sanitization** | Request body sanitization |
| **Secrets Management** | Environment variables, no hardcoded secrets |
| **Audit Logging** | Complete audit trail of all user actions |
| **Access Control** | RBAC with granular permissions |
| **Secure Password Reset** | Token-based password reset with expiration |
| **Session Management** | JWT with short-lived access tokens |
| **XSS Protection** | Content Security Policy, input sanitization |
| **CSRF Protection** | SameSite cookies, token validation |

---

## Security Vulnerability Severity Classification

| Severity | Description | Examples |
|----------|-------------|----------|
| **Critical** | Direct exploitation without authentication, leading to system compromise | SQL Injection, RCE, Authentication Bypass |
| **High** | Exploitation with limited authentication, leading to data breach | Privilege Escalation, Sensitive Data Exposure |
| **Medium** | Exploitation requiring specific conditions or limited impact | XSS, CSRF, Information Disclosure |
| **Low** | Minimal impact, requiring significant effort to exploit | Missing security headers, Deprecated libraries |

---

## Threat Modeling

### Key Attack Vectors

| Attack Vector | Mitigation |
|---------------|------------|
| **JWT Token Theft** | Short-lived tokens, refresh token rotation, HTTPS only |
| **API Abuse** | Rate limiting, request validation, IP blocking |
| **Database Injection** | Mongoose schema validation, parameterized queries |
| **Cross-Site Scripting (XSS)** | CSP headers, input sanitization, output encoding |
| **Cross-Site Request Forgery (CSRF)** | SameSite cookies, token validation |
| **Brute Force Attacks** | Rate limiting, account lockout after failed attempts |
| **Insider Threats** | RBAC, audit logging, least privilege principle |

---

## Acknowledgments

We would like to thank the following individuals and organizations for their contributions to SentinelSOC's security:

- Our dedicated security researchers
- The open-source community for security tools and libraries
- Our users for reporting vulnerabilities responsibly

---

*This security policy is reviewed and updated regularly. Last updated: 2026-08-17.*
