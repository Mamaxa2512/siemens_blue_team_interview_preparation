# Security Scan Report (Automated Attack Surface Analyzer)

**Total Vulnerabilities Found:** 2

---

## 1. [MEDIUM] Missing Strict-Transport-Security Header
**Endpoint:** `http://localhost:3000/`

### Description
The application does not enforce HSTS.

### Impact
Users are vulnerable to Man-in-the-Middle attacks.

### Evidence
<details>
<summary>Click to expand Request / Response</summary>

#### Request
```http
GET http://localhost:3000/
```

#### Response
```http
Header 'Strict-Transport-Security' is missing
```
</details>

---

## 2. [MEDIUM] Missing Content-Security-Policy Header
**Endpoint:** `http://localhost:3000/`

### Description
The application does not define a Content Security Policy (CSP).

### Impact
Increases the risk and potential impact of Cross-Site Scripting (XSS) and other data injection attacks.

### Evidence
<details>
<summary>Click to expand Request / Response</summary>

#### Request
```http
GET http://localhost:3000/
```

#### Response
```http
Header 'Content-Security-Policy' is missing
```
</details>

---

