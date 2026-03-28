# Severity classification for source code findings

---

## Quick decision matrix

```
1. Does exploitation require authentication?
   No  --> potential Critical/High
   Yes (low-privilege) --> potential High/Medium
   Yes (admin-only) --> Medium/Low

2. Does exploitation require victim interaction?
   No  --> +1 severity tier
   Yes --> standard

3. What is the concrete impact?
   RCE / full ATO / mass data exfil --> Critical
   Other users' sensitive data / admin access --> High
   Limited data / self-only impact --> Medium/Low

4. Is scope changed? (attacker pivots beyond target component)
   Yes (SSRF->internal, XSS->ATO) --> Critical/High
   No --> stay at base level
```

---

## Severity definitions

### Critical
- Unauthenticated RCE
- Unauthenticated ATO of any user
- Full cloud credential exposure (admin-level)
- Auth bypass to admin without credentials
- Mass PII/financial data exfil
- Unsanitized deserialization of user input (pickle, Java ObjectInputStream)

**Threshold:** Immediate, severe, widespread. No prerequisites.

### High
- Authenticated RCE
- SQLi with data exfiltration of sensitive tables
- SSRF to internal services / cloud metadata
- IDOR accessing other users' PII/financials
- Stored XSS with session hijack potential
- JWT signature bypass / forgery
- Mass assignment to admin role

**Threshold:** Significant unauthorized access. Some attacker effort required.

### Medium
- Reflected XSS (requires victim click)
- Blind SQLi (confirmed but no data exfil yet)
- IDOR on non-sensitive data
- Blind SSRF (no internal access confirmed)
- Path traversal reading non-sensitive files
- CSRF on sensitive action (password/email change)
- Hardcoded secrets in source (not yet confirmed exploitable)

**Threshold:** Real vulnerability, limited impact or requires interaction.

### Low / not reportable (for this audit)
- Open redirect (standalone, no chain)
- Missing security headers alone
- Self-XSS
- CSRF on login/logout
- Version disclosure without confirmed CVE
- Information-only findings without attack path

**Threshold:** This audit does not report Low findings unless they chain to Medium+.

---

## Severity adjustment rules

**Downgrade when:**
- Attack requires social engineering or victim deception (-1 tier)
- Only works in non-default configurations (-1 tier)
- Requires admin privileges to reach the vuln (-1 to -2 tiers)
- Impact limited to attacker's own data (-2 tiers, usually not reportable)
- Exists only in dev/test code not deployed to production (-1 tier)

**Upgrade when:**
- Multiple findings chain together (report combined severity)
- Finding enables pivot to internal systems (scope change)
- Affects authentication/authorization for all users (blast radius)

---

## CWE mapping quick reference

| Vulnerability | CWE |
|--------------|-----|
| SQL Injection | CWE-89 |
| OS Command Injection | CWE-78 |
| XSS (Reflected) | CWE-79 |
| XSS (Stored) | CWE-79 |
| XSS (DOM) | CWE-79 |
| SSRF | CWE-918 |
| Path Traversal | CWE-22 |
| IDOR / Broken Access Control | CWE-639 |
| Deserialization | CWE-502 |
| SSTI | CWE-1336 |
| Hardcoded Credentials | CWE-798 |
| Missing Auth on Endpoint | CWE-306 |
| Broken Authentication | CWE-287 |
| Mass Assignment | CWE-915 |
| Open Redirect | CWE-601 |
| CSRF | CWE-352 |
| XXE | CWE-611 |
| Prototype Pollution | CWE-1321 |

---

## Confidence levels

| Confidence | Criteria |
|-----------|---------|
| **Confirmed** | Full input-to-sink trace verified in code, no defense neutralizes it |
| **Probable** | Path is clear, but a runtime condition (env var, feature flag) could block it |
| **Theoretical** | Semgrep flagged it, code pattern matches, but context needs runtime verification |

Always state confidence alongside severity. A Confirmed Medium outranks a Theoretical High for remediation priority.
