# NetGuard v5.1 — Security Audit Report
**Date:** 2026-02-16
**Auditor:** Opus Manager

## Summary
9 issues found. 3 Critical fixed. 2 High fixed. 3 Medium (acceptable for localhost tool). 1 Info.

## CRITICAL — Fixed ✅

### 1. Command Injection via IP Address (fw_block / fw_unblock)
- **Severity:** CRITICAL
- **Location:** `fw_block()`, `fw_unblock()`
- **Issue:** IP addresses from user input interpolated directly into `shell=True` subprocess commands.
- **Attack:** `POST /api/block {"ips": ["1.2.3.4\" & calc & \""]}` → arbitrary command execution as ADMIN.
- **Fix:** 
  - Added `is_valid_ip_input()` regex validation (IP, CIDR, range only)
  - Changed all `shell=True` + f-string → `shell=False` + list args (no shell interpretation)

### 2. Command Injection via Rule Name (api_unblock_rule)
- **Severity:** CRITICAL
- **Location:** `api_unblock_rule()`
- **Issue:** `rule_name` from JSON body passed directly to netsh via f-string shell command.
- **Fix:** Added `sanitize_rule_name()` — strips non-alphanumeric chars. Uses list args.

### 3. Unsanitized Firewall Operations (api_unblock_all)
- **Severity:** CRITICAL
- **Location:** `api_unblock_all()`
- **Issue:** Rule names from netsh output used in shell commands without sanitization.
- **Fix:** Uses PowerShell `Get-NetFirewallRule` for names, then list-based netsh delete.

## HIGH — Fixed ✅

### 4. No Input Validation on Block API
- **Severity:** HIGH
- **Location:** `api_block()`
- **Issue:** Any string accepted as IP, including shell metacharacters.
- **Fix:** All IPs validated by `is_valid_ip_input()` before any firewall operation.

### 5. Variable Name Bug (geo_cache vs ip_geo_cache)
- **Severity:** HIGH (functional bug causing silent failures)
- **Location:** `api_blocks()`, `refresh_fw_cache()`
- **Issue:** Code referenced `geo_cache` but variable was `ip_geo_cache` → NameError caught by try/except → empty results.
- **Fix:** All references corrected to `ip_geo_cache`.

## MEDIUM — Acceptable

### 6. No Authentication on Web UI
- **Severity:** MEDIUM
- **Note:** Flask binds to `127.0.0.1:7777` (localhost only). Not exposed to network. Acceptable for a local tool.
- **Recommendation:** If ever exposed, add token-based auth.

### 7. No CSRF Protection
- **Severity:** MEDIUM
- **Note:** POST endpoints have no CSRF tokens. Mitigated by localhost binding + browser same-origin policy.
- **Recommendation:** Add `SameSite=Strict` cookies if auth is added.

### 8. XSS via Process Names
- **Severity:** MEDIUM
- **Note:** Process names from psutil rendered in HTML. Process names on Windows are controlled by installed software — low risk.
- **Recommendation:** Escape HTML in JS template literals (future improvement).

## INFO

### 9. Sensitive Data Exposure
- **Severity:** INFO
- **Note:** Geo-lookup results (ISP, city) displayed in UI. This is the tool's intended function. Only visible on localhost.

## Validation Functions Added
```python
is_valid_ip_input(ip)     # Validates IP, CIDR (/0-/32), and IP ranges
sanitize_rule_name(name)  # Strips dangerous characters from rule names
```

## Conclusion
All Critical and High issues fixed. The tool is safe for local use and distribution.
