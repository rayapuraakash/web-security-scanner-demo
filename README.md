# Web Security Scanner Demo

A lightweight Python tool for **authorized defensive web-security checks**.

It inspects a target URL for common HTTP security headers, cookie security flags, HTTPS usage, redirects, and basic server information.

> **Authorized use only:** Run this scanner only against websites and systems you own or have explicit permission to test.

## Features

* HTTPS check
* Common security-header checks
* Cookie `Secure`, `HttpOnly`, and `SameSite` inspection
* Redirect-chain visibility
* Basic `Server` / `X-Powered-By` header visibility
* JSON report output
* Configurable target through the CLI

## Project Structure

```text
web-security-scanner-demo/
├── scanner/
│   ├── __init__.py
│   └── scanner.py
├── tests/
│   └── test_scanner.py
├── reports/
│   └── .gitkeep
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/rayapuraakash/web-security-scanner-demo.git
cd web-security-scanner-demo
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

Basic scan:

```bash
python -m scanner.scanner https://example.com
```

Save the results as JSON:

```bash
python -m scanner.scanner https://example.com --json reports/example.json
```

## Security Checks

The scanner currently checks:

| Check                     | Purpose                                    |
| ------------------------- | ------------------------------------------ |
| HTTPS                     | Checks whether the final URL uses HTTPS    |
| Content-Security-Policy   | Helps restrict executable content sources  |
| Strict-Transport-Security | Requests HTTPS for future connections      |
| X-Content-Type-Options    | Helps reduce MIME-sniffing risks           |
| X-Frame-Options           | Helps mitigate clickjacking                |
| Referrer-Policy           | Controls referrer information              |
| Permissions-Policy        | Restricts browser features                 |
| Secure cookie flag        | Helps prevent cookies being sent over HTTP |
| HttpOnly cookie flag      | Helps prevent JavaScript access to cookies |
| SameSite cookie flag      | Helps control cross-site cookie sending    |

A missing security header is a **configuration finding**, not proof that a vulnerability is exploitable.

## Example

```text
Target: https://example.com
Final URL: https://example.com/
Status: 200
HTTPS: PASS
Content-Security-Policy: MISSING
Strict-Transport-Security: MISSING
X-Content-Type-Options: PASS
X-Frame-Options: MISSING
Referrer-Policy: PASS
Permissions-Policy: MISSING
Cookies: 0
```

## Running Tests

```bash
python -m unittest discover -s tests
```

## Scope

This project intentionally performs passive configuration checks.

It does **not** perform:

* Exploitation
* Credential attacks
* Brute force
* SQL injection payload testing
* Command injection
* Authentication bypass
* Destructive testing

## Disclaimer

This project is intended for education, defensive security testing, and authorized security assessments.

Always obtain explicit permission before scanning a target.
