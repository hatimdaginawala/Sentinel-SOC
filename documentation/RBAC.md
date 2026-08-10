# SentinelSOC RBAC Documentation

## Overview

SentinelSOC implements a comprehensive **Role-Based Access Control (RBAC)** system that governs what users can see and do within the platform. All access decisions are enforced at the API layer, ensuring that permissions are never bypassed by client-side logic.

---

## Roles

SentinelSOC defines five distinct roles, each with specific responsibilities and permission sets.

### Role Definitions

| Role | Identifier | Description |
|------|------------|-------------|
| **Super Administrator** | `super_admin` | Full system access with all permissions |
| **Security Administrator** | `security_admin` | Manage security infrastructure, assets, and detection rules |
| **SOC Analyst** | `soc_analyst` | Monitor logs, investigate alerts, and manage incidents |
| **Incident Responder** | `incident_responder` | Handle and resolve security incidents |
| **Auditor** | `auditor` | Read-only access for compliance and auditing |

### Role Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                      SUPER ADMINISTRATOR                       │
│                        (Full Access)                           │
├─────────────────────────────────────────────────────────────────┤
│                      SECURITY ADMINISTRATOR                    │
│            (Manage Assets, Rules, Infrastructure)               │
├─────────────────────────────────────────────────────────────────┤
│                       INCIDENT RESPONDER                        │
│              (Handle and Resolve Incidents)                    │
├─────────────────────────────────────────────────────────────────┤
│                         SOC ANALYST                             │
│            (Monitor, Investigate, Manage Alerts)                │
├─────────────────────────────────────────────────────────────────┤
│                           AUDITOR                               │
│                     (Read-Only Access)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Permissions

### Permission List

| Permission | Identifier | Description |
|------------|------------|-------------|
| **User Management** | | |
| Manage Users | `manage_users` | Create, update, delete users |
| View Users | `view_users` | View user list and details |
| **Organization Management** | | |
| Manage Organizations | `manage_organizations` | Create, update, delete organizations |
| View Organizations | `view_organizations` | View organization list and details |
| **Asset Management** | | |
| Manage Assets | `manage_assets` | Create, update, delete assets |
| View Assets | `view_assets` | View asset list and details |
| **Log Management** | | |
| Manage Logs | `manage_logs` | Delete logs, manage retention |
| View Logs | `view_logs` | View log data and statistics |
| **Alert Management** | | |
| Manage Alerts | `manage_alerts` | Update, assign, resolve alerts |
| View Alerts | `view_alerts` | View alert list and details |
| **Incident Management** | | |
| Manage Incidents | `manage_incidents` | Create, update, delete incidents |
| View Incidents | `view_incidents` | View incident list and details |
| Respond Incidents | `respond_incidents` | Resolve, escalate, add evidence |
| **Report Management** | | |
| Manage Reports | `manage_reports` | Create, delete, schedule reports |
| View Reports | `view_reports` | View report list and data |
| Generate Reports | `generate_reports` | Generate and export reports |
| **System Configuration** | | |
| Configure System | `configure_system` | Update system settings |
| View Settings | `view_settings` | View system settings |
| **Audit** | | |
| View Audit Logs | `view_audit_logs` | View audit trail |
| Manage Audit Logs | `manage_audit_logs` | Clean up old audit logs |
| **Threat Intelligence** | | |
| Manage Threat Rules | `manage_threat_rules` | Create, update, delete rules |
| View Threat Rules | `view_threat_rules` | View rule list and details |
| **IOC Management** | | |
| Manage IOCs | `manage_iocs` | Create, update, delete IOCs |
| View IOCs | `view_iocs` | View IOC list and details |

### Permission to Role Mapping

| Permission | Super Admin | Security Admin | SOC Analyst | Incident Responder | Auditor |
|------------|:-----------:|:--------------:|:-----------:|:------------------:|:-------:|
| `manage_users` | ✓ | | | | |
| `view_users` | ✓ | ✓ | | | ✓ |
| `manage_organizations` | ✓ | | | | |
| `view_organizations` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_assets` | ✓ | ✓ | | | |
| `view_assets` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_logs` | ✓ | ✓ | | | |
| `view_logs` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_alerts` | ✓ | ✓ | ✓ | ✓ | |
| `view_alerts` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_incidents` | ✓ | ✓ | ✓ | ✓ | |
| `view_incidents` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `respond_incidents` | ✓ | ✓ | | ✓ | |
| `manage_reports` | ✓ | ✓ | ✓ | | |
| `view_reports` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `generate_reports` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `configure_system` | ✓ | ✓ | | | |
| `view_settings` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `view_audit_logs` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_audit_logs` | ✓ | ✓ | | | |
| `manage_threat_rules` | ✓ | ✓ | | | |
| `view_threat_rules` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `manage_iocs` | ✓ | ✓ | ✓ | ✓ | |
| `view_iocs` | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Authentication

### JWT Authentication

SentinelSOC uses **JSON Web Tokens (JWT)** for stateless authentication.

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                      AUTHENTICATION FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User submits credentials                                     │
│     POST /api/v1/auth/login                                     │
│     { identifier, password }                                    │
│                                                                  │
│  2. Server validates credentials                                 │
│     - Check user exists                                         │
│     - Verify password (bcrypt compare)                          │
│     - Check account status (active/locked)                      │
│     - Check login attempts                                      │
│                                                                  │
│  3. Server generates tokens                                     │
│     - Access Token (expires in 7 days)                          │
│     - Refresh Token (expires in 30 days)                        │
│                                                                  │
│  4. Server returns tokens to client                             │
│     { accessToken, refreshToken, user }                         │
│                                                                  │
│  5. Client stores tokens (localStorage/HTTP-only cookies)      │
│                                                                  │
│  6. Client includes access token in requests                    │
│     Authorization: Bearer <access_token>                        │
│                                                                  │
│  7. Server validates token on protected routes                  │
│     - Verify signature                                          │
│     - Check expiration                                          │
│     - Extract user data                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with email/username and password |
| POST | `/api/v1/auth/refresh` | Refresh access token using refresh token |
| POST | `/api/v1/auth/logout` | Logout and invalidate refresh token |
| POST | `/api/v1/auth/forgot-password` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Complete password reset |

### Token Structure

**Access Token Payload:**
```json
{
  "id": "6a68446a894f7943cb4bb931",
  "email": "superadmin@sentinel-soc.com",
  "username": "superadmin",
  "role": "super_admin",
  "organization": "6a68446a894f7943cb4bb926",
  "iat": 1785218815,
  "exp": 1785823615
}
```

### Security Controls

| Control | Implementation |
|---------|----------------|
| **Password Storage** | bcrypt hashing with salt rounds (12) |
| **Token Expiry** | Access token: 7 days, Refresh token: 30 days |
| **Token Rotation** | New refresh token issued on each refresh |
| **Session Management** | Stateless (no server-side session storage) |
| **Logout** | Refresh token invalidated on server |

---

## Authorization

### RBAC Middleware

Authorization is enforced using a middleware chain that checks permissions before allowing access to routes.

### Middleware Architecture

```javascript
// routes/users.js
router.get('/users',
  protect,                    // 1. Verify JWT token
  authorize('view_users'),    // 2. Check permission
  UserController.getUsers     // 3. Execute handler
);
```

### Middleware Implementation

#### 1. Protect Middleware

Verifies JWT token and attaches user to request.

```javascript
// middleware/auth.js
const protect = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      throw new AppError('Not logged in', 401);
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user from database
    const user = await User.findById(decoded.id)
      .populate('organization');
    
    if (!user) {
      throw new AppError('User not found', 401);
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};
```

#### 2. Authorize Middleware

Checks if user has required permissions.

```javascript
// middleware/auth.js
const authorize = (...permissions) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Not authenticated', 403);
      }

      // Super admin bypass
      if (req.user.role === 'super_admin') {
        return next();
      }

      // Check permissions
      const hasPermission = permissions.some(permission =>
        req.user.permissions?.includes(permission)
      );

      if (!hasPermission) {
        throw new AppError('Insufficient permissions', 403);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
```

#### 3. Authorize by Role

Alternative role-based authorization.

```javascript
// middleware/auth.js
const authorizeRole = (...roles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new AppError('Not authenticated', 403);
      }

      if (!roles.includes(req.user.role)) {
        throw new AppError('Insufficient role', 403);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
```

---

## API Permission Matrix

### Authentication Endpoints (Public)

| Endpoint | Method | Authentication | Permissions |
|----------|--------|----------------|-------------|
| `/auth/login` | POST | None | None |
| `/auth/refresh` | POST | Refresh Token | None |
| `/auth/forgot-password` | POST | None | None |
| `/auth/reset-password` | POST | None | None |
| `/auth/logout` | POST | JWT | None |

### User Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/users` | GET | JWT | `view_users` |
| `/users/me` | GET | JWT | None (self) |
| `/users/:id` | GET | JWT | `view_users` |
| `/users` | POST | JWT | `manage_users` |
| `/users/:id` | PUT | JWT | `manage_users` |
| `/users/:id` | DELETE | JWT | `manage_users` |
| `/users/change-password` | POST | JWT | None (self) |
| `/users/:id/reset-password` | POST | JWT | `manage_users` |

### Organization Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/organizations` | GET | JWT | `view_organizations` |
| `/organizations/:id` | GET | JWT | `view_organizations` |
| `/organizations` | POST | JWT | `manage_organizations` |
| `/organizations/:id` | PUT | JWT | `manage_organizations` |
| `/organizations/:id` | DELETE | JWT | `manage_organizations` |

### Asset Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/assets` | GET | JWT | `view_assets` |
| `/assets/:id` | GET | JWT | `view_assets` |
| `/assets` | POST | JWT | `manage_assets` |
| `/assets/:id` | PUT | JWT | `manage_assets` |
| `/assets/:id` | DELETE | JWT | `manage_assets` |
| `/assets/statistics` | GET | JWT | `view_assets` |

### Log Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/logs/ingest` | POST | Source Token | None (public) |
| `/logs` | GET | JWT | `view_logs` |
| `/logs/:id` | GET | JWT | `view_logs` |
| `/logs/statistics` | GET | JWT | `view_logs` |
| `/logs/:id` | DELETE | JWT | `manage_logs` |
| `/logs/cleanup` | POST | JWT | `manage_logs` |

### Alert Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/alerts` | GET | JWT | `view_alerts` |
| `/alerts/:id` | GET | JWT | `view_alerts` |
| `/alerts` | POST | JWT | `manage_alerts` |
| `/alerts/:id` | PUT | JWT | `manage_alerts` |
| `/alerts/:id/assign` | POST | JWT | `manage_alerts` |
| `/alerts/:id/resolve` | POST | JWT | `manage_alerts` |
| `/alerts/:id/escalate` | POST | JWT | `manage_alerts` |
| `/alerts/:id` | DELETE | JWT | `manage_alerts` |
| `/alerts/statistics` | GET | JWT | `view_alerts` |

### Incident Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/incidents` | GET | JWT | `view_incidents` |
| `/incidents/:id` | GET | JWT | `view_incidents` |
| `/incidents` | POST | JWT | `manage_incidents` |
| `/incidents/:id` | PUT | JWT | `manage_incidents` |
| `/incidents/:id/assign` | POST | JWT | `manage_incidents` |
| `/incidents/:id/resolve` | POST | JWT | `respond_incidents` |
| `/incidents/:id/close` | POST | JWT | `respond_incidents` |
| `/incidents/:id/escalate` | POST | JWT | `respond_incidents` |
| `/incidents/:id/evidence` | POST | JWT | `respond_incidents` |
| `/incidents/:id` | DELETE | JWT | `manage_incidents` |
| `/incidents/statistics` | GET | JWT | `view_incidents` |

### Threat Rule Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/threat-rules` | GET | JWT | `view_threat_rules` |
| `/threat-rules/:id` | GET | JWT | `view_threat_rules` |
| `/threat-rules` | POST | JWT | `manage_threat_rules` |
| `/threat-rules/:id` | PUT | JWT | `manage_threat_rules` |
| `/threat-rules/:id` | DELETE | JWT | `manage_threat_rules` |
| `/threat-rules/:id/toggle` | PATCH | JWT | `manage_threat_rules` |
| `/threat-rules/statistics` | GET | JWT | `view_threat_rules` |

### IOC Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/iocs` | GET | JWT | `view_iocs` |
| `/iocs/:id` | GET | JWT | `view_iocs` |
| `/iocs` | POST | JWT | `manage_iocs` |
| `/iocs/:id` | PUT | JWT | `manage_iocs` |
| `/iocs/:id` | DELETE | JWT | `manage_iocs` |
| `/iocs/:id/link-incident` | POST | JWT | `manage_iocs` |
| `/iocs/:id/link-alert` | POST | JWT | `manage_iocs` |

### Audit Log Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/audit-logs` | GET | JWT | `view_audit_logs` |
| `/audit-logs/:id` | GET | JWT | `view_audit_logs` |
| `/audit-logs/statistics` | GET | JWT | `view_audit_logs` |
| `/audit-logs/cleanup` | POST | JWT | `manage_audit_logs` |

### Report Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/reports` | GET | JWT | `view_reports` |
| `/reports/:id` | GET | JWT | `view_reports` |
| `/reports` | POST | JWT | `manage_reports` |
| `/reports/:id` | PUT | JWT | `manage_reports` |
| `/reports/:id` | DELETE | JWT | `manage_reports` |
| `/reports/:id/generate` | POST | JWT | `generate_reports` |
| `/reports/:id/schedule` | POST | JWT | `manage_reports` |

### Settings Endpoints

| Endpoint | Method | Auth | Permission Required |
|----------|--------|------|---------------------|
| `/settings` | GET | JWT | `view_settings` |
| `/settings` | PUT | JWT | `configure_system` |
| `/settings/:path` | GET | JWT | `view_settings` |
| `/settings/:path` | PATCH | JWT | `configure_system` |
| `/settings/security` | GET | JWT | `view_settings` |
| `/settings/security` | PUT | JWT | `configure_system` |
| `/settings/reset` | POST | JWT | `configure_system` |

---

## Permission Checking

### Service-Level Permission Checks

Permissions are also enforced at the service layer for defense in depth:

```javascript
// services/userService.js
async updateUser(userId, updateData, updatedBy) {
  // Verify caller has permission
  const caller = await User.findById(updatedBy);
  if (!caller.hasPermission('manage_users')) {
    throw new AppError('Insufficient permissions', 403);
  }
  
  // Proceed with update
  // ...
}
```

### Frontend Permission Checks

The frontend uses permissions to show/hide UI elements:

```javascript
// frontend/assets/js/auth.js
class Auth {
  static hasPermission(permission) {
    const user = this.getCurrentUser();
    if (!user) return false;
    if (user.role === 'super_admin') return true;
    return user.permissions?.includes(permission) || false;
  }

  static enforcePermission(permission) {
    if (!this.hasPermission(permission)) {
      window.location.href = '/pages/login.html';
      return false;
    }
    return true;
  }
}
```

### UI Permission Examples

```html
<!-- Show only if user has manage_users permission -->
<div id="user-management-section" style="display: none;">
  <!-- User management UI -->
</div>

<script>
if (Auth.hasPermission('manage_users')) {
  document.getElementById('user-management-section').style.display = 'block';
}
</script>
```

---

## User-Specific Access Control

### Own Data Access

Users can access their own data without explicit permissions:

```javascript
// controllers/userController.js
getCurrentUser = asyncHandler(async (req, res) => {
  // No permission check needed - user is accessing own data
  const user = await UserService.getUserById(req.user.id);
  ResponseHandler.success(res, user);
});

changePassword = asyncHandler(async (req, res) => {
  // User can change their own password
  const { oldPassword, newPassword } = req.body;
  await UserService.changePassword(req.user.id, oldPassword, newPassword);
  ResponseHandler.success(res, null, 'Password changed');
});
```

### Organization Scoping

All data is scoped by organization:

```javascript
// services/assetService.js
async getAssetsByOrganization(organizationId, filters = {}) {
  // Ensure user belongs to the organization
  const user = await User.findById(this.userId);
  if (user.organization.toString() !== organizationId) {
    throw new AppError('Access denied', 403);
  }
  
  return await Asset.find({ organization: organizationId });
}
```

---

## Error Handling

### Authorization Errors

**403 Forbidden Response:**
```json
{
  "success": false,
  "message": "You do not have permission to perform this action.",
  "errorCode": "INSUFFICIENT_PERMISSIONS",
  "timestamp": "2026-07-29T17:21:00.000Z",
  "path": "/api/v1/users"
}
```

### Authentication Errors

**401 Unauthorized Response:**
```json
{
  "success": false,
  "message": "Invalid token. Please log in again.",
  "errorCode": "INVALID_TOKEN",
  "timestamp": "2026-07-29T17:21:00.000Z",
  "path": "/api/v1/users"
}
```

---

## Default System Roles

### Super Administrator

```javascript
{
  name: 'super_admin',
  displayName: 'Super Administrator',
  description: 'Complete system access with all permissions',
  permissions: [
    'manage_users', 'view_users', 'manage_organizations', 'view_organizations',
    'manage_assets', 'view_assets', 'manage_logs', 'view_logs',
    'manage_alerts', 'view_alerts', 'manage_incidents', 'view_incidents', 'respond_incidents',
    'manage_reports', 'view_reports', 'generate_reports',
    'configure_system', 'view_settings',
    'view_audit_logs', 'manage_audit_logs',
    'manage_threat_rules', 'view_threat_rules',
    'manage_iocs', 'view_iocs'
  ],
  isSystem: true,
  priority: 100
}
```

### Security Administrator

```javascript
{
  name: 'security_admin',
  displayName: 'Security Administrator',
  description: 'Manage security infrastructure, assets, and rules',
  permissions: [
    'view_users', 'view_organizations',
    'manage_assets', 'view_assets',
    'manage_logs', 'view_logs',
    'view_alerts', 'view_incidents',
    'manage_threat_rules', 'view_threat_rules',
    'view_reports', 'generate_reports',
    'view_settings', 'manage_audit_logs'
  ],
  isSystem: true,
  priority: 80
}
```

### SOC Analyst

```javascript
{
  name: 'soc_analyst',
  displayName: 'SOC Analyst',
  description: 'Monitor and investigate security events',
  permissions: [
    'view_organizations', 'view_assets',
    'view_logs', 'view_alerts', 'manage_alerts',
    'view_incidents', 'manage_incidents',
    'view_threat_rules',
    'view_reports', 'generate_reports'
  ],
  isSystem: true,
  priority: 60
}
```

### Incident Responder

```javascript
{
  name: 'incident_responder',
  displayName: 'Incident Responder',
  description: 'Handle and resolve security incidents',
  permissions: [
    'view_organizations', 'view_assets',
    'view_logs', 'view_alerts', 'manage_alerts',
    'view_incidents', 'manage_incidents', 'respond_incidents',
    'view_threat_rules',
    'view_reports', 'generate_reports'
  ],
  isSystem: true,
  priority: 70
}
```

### Auditor

```javascript
{
  name: 'auditor',
  displayName: 'Auditor',
  description: 'Read-only access for compliance and auditing',
  permissions: [
    'view_users', 'view_organizations',
    'view_assets', 'view_logs', 'view_alerts', 'view_incidents',
    'view_threat_rules', 'view_iocs',
    'view_reports', 'view_settings',
    'view_audit_logs'
  ],
  isSystem: true,
  priority: 40
}
```

---

## Quick Reference

### Common Permission Checks

```javascript
// Controller level
router.get('/users', protect, authorize('view_users'), handler);

// Service level
if (!user.hasPermission('manage_users')) {
  throw new AppError('Insufficient permissions', 403);
}

// Frontend level
if (Auth.hasPermission('manage_incidents')) {
  // Show incident management UI
}

// Template level
<% if (hasPermission('manage_alerts')) { %>
  <button>Create Alert</button>
<% } %>
```

### Permission String Format

Permissions follow the format: `{action}_{resource}`

- **Action**: `manage`, `view`, `create`, `update`, `delete`, `respond`, `generate`, `configure`
- **Resource**: `users`, `organizations`, `assets`, `logs`, `alerts`, `incidents`, `iocs`, `threat_rules`, `reports`, `settings`, `audit_logs`

### Testing Permissions

```bash
# Check user permissions
curl -X GET http://localhost:3000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_TOKEN"

# Response includes permissions
{
  "data": {
    "id": "6a68446a894f7943cb4bb931",
    "email": "superadmin@sentinel-soc.com",
    "role": "super_admin",
    "permissions": [
      "manage_users",
      "view_users"
    ]}
  }

```