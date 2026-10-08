# Strict Read-Only Account & History Recovery Audit Report

**Date & Time**: 2026-10-08T19:28:00+05:30  
**Audit Scope**: Read-Only Forensic Database & Authentication Audit  
**Status**: Completed (Zero Database Modifications Performed)

---

## 1. Active Database Identification

- **Active Database Path**: `C:\Users\Singh Adarsh\.gemini\antigravity\scratch\ps5-scam-shield\backend\data\scam_shield.db`
- **Database Exists**: **YES**
- **Database File Size**: `3,923,968 bytes (~3.92 MB)`
- **Last Modified**: `2026-10-08 19:14:46`
- **Database Status**: Active SQLite 3 database with WAL journal mode and foreign keys enabled.

### Database File Inventory across Workspace
Only one SQLite database file exists in the workspace:
- `backend/data/scam_shield.db` (Primary production database)

---

## 2. Table Inventory

All core database tables exist and are intact:

| Table Name | Status | Purpose |
| :--- | :--- | :--- |
| `users` | **EXISTS** | User authentication accounts and roles |
| `scans` | **EXISTS** | Scan metadata, input targets, risk scores, and user bindings |
| `evidence` | **EXISTS** | Granular forensic evidence signals per scan |
| `reports` | **EXISTS** | Fraud and security incident reports |
| `feedback` | **EXISTS** | User accuracy feedback |
| `model_metadata` | **EXISTS** | Active & archived ML model versions and metrics |
| `audit_events` | **EXISTS** | Forensic audit log events |

---

## 3. User Account Inventory (Safe Recovery Identifiers)

Total registered accounts in database: **48** (including test runner accounts).

### Identified Human User Accounts

1. **Primary Original Account**:
   - **User ID**: `usr_musrexv8_3rbg`
   - **Login Email**: `me@gmail.com`
   - **Role**: `user`
   - **Created At**: `2026-10-03 19:02:59`
   - **Bound Scans**: **36 scans**
   - **Bound Reports**: **2 incident reports**

2. **Secondary Account**:
   - **User ID**: `usr_muzlbfzm_kpx0`
   - **Login Email**: `1032241834@tcetmumbai.in`
   - **Role**: `user`
   - **Created At**: `2026-10-08 13:46:42`
   - **Bound Scans**: **1 scan**
   - **Bound Reports**: **0 incident reports**

> [!NOTE]
> All password hashes, JWT secrets, and tokens were strictly kept confidential and not outputted.

---

## 4. Scan & Report History Metrics

- **Total Scans in Database**: **2,268 scans**
  - **Authenticated User Scans (`user_id IS NOT NULL`)**: **64 scans**
    - Account `me@gmail.com` (`usr_musrexv8_3rbg`): **36 scans**
    - Account `1032241834@tcetmumbai.in` (`usr_muzlbfzm_kpx0`): **1 scan**
    - Automated test runner users: **27 scans**
  - **Anonymous / Guest Scans (`user_id IS NULL`)**: **2,204 scans**

- **Total Fraud Incident Reports**: **5 reports**
  - Bound to `me@gmail.com` (`usr_musrexv8_3rbg`): **2 reports** (`rep_mustur9c_6dpg`, `rep_mutsivwr_8zdl`)
  - Bound to Test Users: **2 reports**
  - Anonymous / Historic: **1 report**

---

## 5. Cause Analysis: Data Deleted vs Hidden by Authorization

### Findings
- **Data was NOT deleted**: All 36 historical scans and 2 incident reports belonging to `me@gmail.com` are **100% present and intact** in `scam_shield.db`.
- **Reason History Is Not Visible in UI**:
  1. The browser currently does not have an active authenticated session (user is in guest mode).
  2. Following the Data Isolation update, `GET /api/v1/scans` requires authentication and strictly scopes records to the active session (`WHERE user_id = req.user.id`).
  3. When an unauthenticated visitor accesses `/history`, the platform presents the **Sign In Required** gate to protect private user records from public exposure.

---

## 6. Migration History Audit

- `src/database/migrations.ts` uses `CREATE TABLE IF NOT EXISTS` and `INSERT OR REPLACE INTO model_metadata`.
- No migration commands dropped tables, truncated scan tables, or removed user accounts.
- The database schema and data integrity were fully preserved.

---

## 7. Credential Recovery & Recommended Next Steps

- **Existing Account Found**: **YES** (`me@gmail.com`)
- **Password Recoverable from Database**: **NO** (Passwords are hashed with one-way salted `bcrypt`).
- **Application Password-Reset Feature**: The application currently has standard `/register` and `/login` endpoints, but no automated SMTP email password-reset endpoint.

### Recommended Next Safe Action
When the user is ready:
1. If the user remembers their password for `me@gmail.com`, simply sign in at `/login` to immediately restore access to all 36 scans and 2 incident reports.
2. If the password is forgotten, a secure offline password update script can be run on request to assign a new temporary password to `me@gmail.com` without touching any existing scan data.

---

## Final Audit Verdict

```text
B. ACCOUNT EXISTS + HISTORY IS HIDDEN BY AUTHORIZATION
```
