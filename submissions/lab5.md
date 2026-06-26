# Lab 5 - Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: 10
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~6.5 minutes (spider 18s, AJAX spider 1m 8s, activeScan 5m 19s)
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 12 / 10 = **1.2×**
- The lecture's 10–20× claim did not reproduce on Juice Shop. The reason is that the baseline scan already runs passive checks against all reachable URLs and flags many configuration issues (missing CSP headers, cache policies, etc.) regardless of auth state. The real value of the authenticated scan was in the **active scan** phase, which found SQL Injection - the only High severity alert that the baseline could not have found passively.
- **Two auth-only alerts:**

  1. **SQL Injection (High)** - `/rest/products/search?q='(`. The unauthenticated baseline only runs passive checks (no attack payloads), so it cannot detect SQLi. Active scanning required.
  2. **Session ID in URL Rewrite (Medium)** - `socket.io` WebSocket transport endpoints. The AJAX spider discovered WebSocket-based communication paths that the baseline spider couldn't reach, exposing session IDs in URL query parameters.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A03 Injection |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07 Identification Failure |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
I would fix **`express-sequelize-injection`** first. It accounts for 6 out of 22 findings (27% of all issues) and maps to **OWASP A03 - Injection**, which is the most critical category. More importantly, these SQLi findings are concentrated in a single pattern - raw string interpolation in `sequelize.query()` calls. One fix applied at the query layer (migrating to parameterized queries via `replacements: {}`) would remediate all 6 instances at once, including the vulnerable search and login endpoints that are also confirmed exploitable by ZAP.

### False-positive sample
**Path:** `.github/workflows/update-challenges-ebook.yml` (rule: `run-shell-injection`)

The rule flags `${{ github.ref_name }}` in `wget` and `cp` commands inside GitHub Actions `run:` steps as potential shell injection. However, `github.ref_name` is a trusted context variable set by GitHub itself - it can only be `master` or a branch/tag name controlled by users with push access to the repository. An attacker would already need commit access to exploit this, making the finding effectively a false positive in this specific context. The rule is correct in principle but over-approximates here.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `GET http://juice-shop:3000/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection | `POST http://juice-shop:3000/rest/user/login` (payload: `'`) | `express-sequelize-injection` | `routes/login.ts:34` | High (both agree) |

### Strongest correlation deep-dive

**Vulnerable code** - `routes/search.ts:23` (Semgrep):
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR
    description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

The `criteria` variable comes directly from `req.query.q` without sanitization, and the string interpolation embeds it directly into the SQL query.

**Working payload** - from ZAP authenticated scan:
```
GET /rest/products/search?q='(
→ HTTP/1.1 500 Internal Server Error
```

The single quote (`'`) breaks the SQL string delimiter, and the open parenthesis `(` triggers a syntax error in the SQLite parser, confirming injection.

**Proposed fix** - use Sequelize parameterized replacements:
```typescript
models.sequelize.query(
    `SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name`,
    { replacements: { q: `%${criteria}%` } }
)
```

This separates the SQL structure from user data. Even if `criteria` contains `' OR '1'='1`, it will be treated as a literal string value by the database engine rather than executable SQL.

**Why both tools caught it:**
- **SAST** (Semgrep) saw the source code pattern: user-controlled `req.query.q` flowing into a `sequelize.query()` call with template literal interpolation - a syntactic red flag.
- **DAST** (ZAP) confirmed it dynamically: sending `'(` as the `q` parameter caused a 500 Internal Server Error, proving the input reached SQL parser and broke the query. The static pattern matched the vulnerable code path, and the dynamic probe proved it was reachable and exploitable.

### Reflection
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review, I would want the **DAST evidence first** - the payload and the 500 error are undeniable proof that the bug exists and is reachable. The Semgrep finding then serves as the precise location pin: "line 23, this exact interpolation." Together they tell the full story: "here's the exploit, and here's exactly which line to fix." Neither alone gives both the *what* and the *where*.