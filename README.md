#  Custom Web Application Firewall (WAF)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen)]()

A **lightweight and customizable Web Application Firewall (WAF)** built with FastAPI, acting as a reverse proxy to protect web applications against common attacks (SQL Injection, XSS, Path Traversal, Command Injection, and more).

**Use cases:** Security lab environments, vulnerable app protection, OWASP Juice Shop defense, penetration testing, WAF bypass research.

---

##  Table of Contents

- [Project Objectives](#-project-objectives)
- [Architecture](#-architecture)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Testing & Validation](#-testing--validation)
- [Logs & Monitoring](#-logs--monitoring)
- [Detailed Architecture](#-detailed-architecture)
- [Security Rules](#-security-rules)
- [API Documentation](#-api-documentation)
- [Contributing](#-contributing)
- [Resources](#-resources)

---

##  Project Objectives

 Understand how a Web Application Firewall (WAF) works  
 Protect web applications against OWASP Top 10 attacks  
 Implement custom detection rules  
 Analyze and log attack attempts  
 Serve as a learning foundation for web security  
 Enable red team testing and WAF evasion research  

---

##  Architecture

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT / ATTACKER                        │
│                  (Parrot OS, Burp Suite)                    │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/HTTPS Requests
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           CUSTOM WAF (FastAPI - Port 8080)                  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Request Inspection Module                            │  │
│  │  • SQL Injection Detection                            │  │
│  │  • XSS (Cross-Site Scripting) Protection              │  │
│  │  • Path Traversal Prevention                          │  │
│  │  • Command Injection Detection                        │  │
│  │  • Request Normalization                              │  │
│  │  • Sensitive File Access Protection                   │  │
│  │  • Rate Limiting (optional)                           │  │
│  └───────────────────────────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────▼──────────────────────────────┐    │
│  │  Logging & Alerting System                          │    │
│  │  • File-based logging (JSON/Text)                   │    │
│  │  • Request/Response tracking                        │    │
│  │  • Threat Level Classification                      │    │
│  │  • Real-time Alerts                                 │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────┬────────────────────────────────────┘
                         │ Forwarded Requests (Safe)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│      TARGET APPLICATION (OWASP Juice Shop - Port 3000)      │
│                                                             │
│  Node.js Express Backend                                    │
│  Intentionally Vulnerable Web Application                   │
└─────────────────────────────────────────────────────────────┘
```

### Request Processing Flow

```
1. Client sends HTTP request
   ↓
2. WAF receives request (Port 8080)
   ↓
3. Request Normalization:
   - URL decoding
   - Special character handling
   - Encoding standardization
   ↓
4. Rule-based Inspection:
   ├─ SQL Injection patterns
   ├─ XSS payloads
   ├─ Path Traversal sequences
   ├─ Command Injection attempts
   ├─ Sensitive file patterns
   └─ Custom rules
   ↓
5. Decision:
   ├─  SAFE → Forward to backend → Log request
   └─  BLOCKED → Return 403 Forbidden → Log threat with details
```

---

##  Features

###  Detection & Protection

| Attack Type | Status | Details |
|-------------|--------|---------|
| **SQL Injection** |  Enabled | Detects common SQL patterns (`OR 1=1`, `UNION SELECT`, `DROP TABLE`, etc.) |
| **Cross-Site Scripting (XSS)** |  Enabled | Blocks malicious scripts and event handlers |
| **Path Traversal** |  Enabled | Prevents directory traversal (`../`, `..\\`) and sensitive file access |
| **Command Injection** |  Enabled | Detects shell metacharacters (`;`, `\|`, `&`, backticks, etc.) |
| **Sensitive Files** |  Enabled | Protects `/etc/passwd`, `/.env`, `/config.php`, `/database.yml`, etc. |
| **Request Normalization** |  Enabled | Anti-bypass via URL encoding and normalization |
| **Rate Limiting** |  WIP | Coming soon |
| **GEO-Blocking** |  WIP | IP-based geolocation blocking |

###  Monitoring & Logging

-  Structured logging (JSON/Text format)
-  Complete request → response tracing
-  Threat classification (LOW, MEDIUM, HIGH, CRITICAL)
-  Attack statistics and aggregation
-  Real-time alerts and notifications
-  Customizable log retention

###  Use Cases

1. **Security Lab** : Learn how WAFs work
2. **Testing Environment** : Secure a vulnerable web application
3. **Red Team Operations** : Test WAF detection and evasion techniques
4. **Penetration Testing** : Analyze WAF rule effectiveness
5. **Development** : Protect development/staging environments

---

##  Prerequisites

```bash
# Operating System
- Linux / macOS / Windows (WSL recommended)

# Required Software
- Python 3.8 or higher
- Node.js 14+ (if using OWASP Juice Shop)
- pip (Python package manager)
- Git

# Optional
- Docker (for containerization)
- Burp Suite Community (for security testing)
- Parrot OS or Kali Linux (for attack simulation)
- Virtual Machine Manager (VirtualBox, Proxmox, etc.)
```

### Verify Prerequisites

```bash
python --version          # Should be 3.8+
pip --version
node --version            # If using Juice Shop
git --version
```

---

##  Installation

### 1 Clone the Repository

```bash
git clone https://github.com/AdamBelbaraka/Web-Application-Firewall-Custom-One-.git
cd Web-Application-Firewall---Custom-One-
```

### 2 Create Virtual Environment

```bash
# Linux / macOS
python -m venv venv
source venv/bin/activate

# Windows (CMD)
python -m venv venv
venv\Scripts\activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3 Install Dependencies

```bash
pip install -r requirements.txt
```

**Contents of `requirements.txt`:**

```
fastapi==0.104.1
uvicorn==0.24.0
httpx==0.25.0
python-dotenv==1.0.0
pydantic==2.5.0
```

### 4 Configuration (Optional)

Create a `.env` file in the project root:

```env
# WAF Configuration
BACKEND_URL=http://127.0.0.1:3000
WAF_PORT=8080
WAF_HOST=0.0.0.0

# Logging Configuration
LOG_FILE=./logs/waf.log
LOG_LEVEL=INFO
LOG_FORMAT=json

# Security Settings
ENABLE_REQUEST_LOGGING=true
ENABLE_RESPONSE_LOGGING=false
MAX_REQUEST_SIZE=10485760  # 10MB

# Optional: HTTPS Configuration (Future)
# SSL_CERT=/path/to/cert.pem
# SSL_KEY=/path/to/key.pem
```

---

##  Quick Start

### Option 1: WAF Only

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Start the WAF
python main.py

# Expected output:
# ℹ  Uvicorn running on http://0.0.0.0:8080
# ℹ  Application startup complete
```

The WAF will be accessible at: **http://localhost:8080**

### Option 2: WAF + OWASP Juice Shop (Full Stack)

```bash
# Terminal 1 - Start OWASP Juice Shop (Port 3000)
npm start                 # If cloned locally
# or
docker run -p 3000:3000 bkimminich/juice-shop

# Terminal 2 - Start the WAF (Port 8080)
source venv/bin/activate
python main.py
```

Access points:
- **WAF Proxy** : http://localhost:8080 (Protected)
- **Juice Shop via WAF** : http://localhost:8080 (Redirects to 3000)
- **Juice Shop Direct** : http://localhost:3000 (Unprotected)

---

##  Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://127.0.0.1:3000` | Target URL (backend application to protect) |
| `WAF_PORT` | `8080` | WAF listening port |
| `WAF_HOST` | `0.0.0.0` | WAF listening interface |
| `LOG_FILE` | `./logs/waf.log` | Log file path |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `ENABLE_REQUEST_LOGGING` | `true` | Log incoming requests |
| `ENABLE_RESPONSE_LOGGING` | `false` | Log responses (may impact performance) |
| `MAX_REQUEST_SIZE` | `10485760` | Maximum request size in bytes (10MB) |

### Customizing Security Rules

**Edit `main.py` to modify detection rules:**

```python
# SQL Injection patterns (regex)
SQL_PATTERNS = [
    r"(\bOR\b\s*1\s*=\s*1)",
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bDROP\b\s+\bTABLE\b)",
    r"(\bINSERT\b.*\bVALUES\b)",
    # Add more patterns...
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    # Add more patterns...
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.{2}/",
    r"\.{2}\\",
    r"%2e%2e",
    # Add more patterns...
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS = [
    r";\s*\w+",
    r"\|\s*\w+",
    r"&&\s*\w+",
    r"`.*`",
    # Add more patterns...
]
```

---

##  Testing & Validation

### Test 1: SQL Injection

```bash
# Normal request (SAFE)
curl "http://localhost:8080/search?id=1"

# SQL Injection attempt (BLOCKED)
curl "http://localhost:8080/search?id=1 OR 1=1"

# Expected result:
#  403 Forbidden
# Error message: "SQL Injection detected in parameter 'id'"
```

### Test 2: XSS Attack

```bash
# Normal request (SAFE)
curl "http://localhost:8080/feedback?msg=Hello"

# XSS payload (BLOCKED)
curl "http://localhost:8080/feedback?msg=<script>alert('XSS')</script>"

# Expected result:
#  403 Forbidden
# Error message: "XSS detected in parameter 'msg'"
```

### Test 3: Path Traversal

```bash
# Normal request (SAFE)
curl "http://localhost:8080/files/document.pdf"

# Path traversal attempt (BLOCKED)
curl "http://localhost:8080/files/../../etc/passwd"

# Expected result:
#  403 Forbidden
# Error message: "Path traversal detected"
```

### Test 4: Command Injection

```bash
# Normal request (SAFE)
curl "http://localhost:8080/ping?host=8.8.8.8"

# Command injection attempt (BLOCKED)
curl "http://localhost:8080/ping?host=8.8.8.8; cat /etc/passwd"

# Expected result:
#  403 Forbidden
# Error message: "Command injection detected"
```

### Testing with Burp Suite

1. Configure Burp Suite proxy listener on `127.0.0.1:8080`
2. Set your browser to use Burp as proxy
3. Navigate to `http://localhost:8080`
4. Send test payloads from **Intruder** or **Repeater**
5. Monitor WAF logs for detections

### Automated Testing with curl

```bash
# Create a test script (test_waf.sh)
#!/bin/bash

BASE_URL="http://localhost:8080"

# Test 1: SQL Injection
echo "Testing SQL Injection..."
curl -s "$BASE_URL/search?id=1 OR 1=1" -w "\nStatus: %{http_code}\n"

# Test 2: XSS
echo "Testing XSS..."
curl -s "$BASE_URL/feedback?msg=<script>alert(1)</script>" -w "\nStatus: %{http_code}\n"

# Test 3: Path Traversal
echo "Testing Path Traversal..."
curl -s "$BASE_URL/files/../../etc/passwd" -w "\nStatus: %{http_code}\n"

# Run tests
bash test_waf.sh
```

---

##  Logs & Monitoring

### Log Format

Each request is logged in JSON format for easy parsing:

```json
{
  "timestamp": "2026-05-06T14:30:45.123Z",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "path": "/search",
  "query_params": "?id=1 OR 1=1",
  "threat_detected": true,
  "threat_type": "SQL_INJECTION",
  "threat_severity": "HIGH",
  "blocked": true,
  "status_code": 403,
  "response_time_ms": 2.34,
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
  "request_body_size": 0,
  "response_size": 142
}
```

### Viewing Logs in Real-Time

```bash
# Watch logs as they happen
tail -f logs/waf.log

# Filter by threat detection
grep "threat_detected" logs/waf.log | grep "true"

# Count total attacks
grep "threat_detected" logs/waf.log | grep "true" | wc -l

# Attacks by type
grep "threat_type" logs/waf.log | cut -d'"' -f4 | sort | uniq -c | sort -rn
```

### Log Analysis Examples

```bash
# Top 10 attacking IPs
grep "threat_detected" logs/waf.log | grep "true" | \
  cut -d'"' -f6 | sort | uniq -c | sort -rn | head -10

# Requests blocked by hour
grep "blocked" logs/waf.log | grep "true" | \
  cut -d'T' -f2 | cut -d':' -f1 | sort | uniq -c

# Most common attack types
grep "threat_type" logs/waf.log | \
  cut -d'"' -f4 | sort | uniq -c | sort -rn

# Success rate
echo "Blocked: $(grep 'blocked.*true' logs/waf.log | wc -l)"
echo "Allowed: $(grep 'blocked.*false' logs/waf.log | wc -l)"
```

### Creating a Log Dashboard

```bash
#!/bin/bash
# Simple log dashboard (run periodically)

echo " WAF Statistics "
echo "Total Requests: $(wc -l < logs/waf.log)"
echo "Attacks Blocked: $(grep 'blocked.*true' logs/waf.log | wc -l)"
echo "Success Rate: $(echo "scale=2; $(grep 'blocked.*false' logs/waf.log | wc -l) * 100 / $(wc -l < logs/waf.log)" | bc)%"
echo ""
echo " Top Threats "
grep "threat_type" logs/waf.log | cut -d'"' -f4 | sort | uniq -c | sort -rn | head -5
echo ""
echo " Top Attacking IPs "
grep "client_ip" logs/waf.log | cut -d'"' -f4 | sort | uniq -c | sort -rn | head -5
```

---

##  Detailed Architecture

### Project Structure

```
Web-Application-Firewall---Custom-One-/
├── main.py                 # Main entry point (FastAPI application)
├── requirements.txt        # Python dependencies
├── .env                    # Configuration (local, not committed)
├── .gitignore              # Git ignore rules
├── README.md               # This file
│
├── waf/                    # WAF package (optional modular structure)
│   ├── __init__.py
│   ├── inspector.py        # Request inspection engine
│   ├── rules.py            # Rule definitions and patterns
│   ├── logger.py           # Logging system
│   └── utils.py            # Utility functions
│
├── logs/                   # Log directory (auto-created)
│   └── waf.log            # Main WAF log file
│
├── tests/                  # Unit and integration tests
│   ├── test_sql_injection.py
│   ├── test_xss.py
│   ├── test_path_traversal.py
│   └── test_command_injection.py
│
├── config/                 # Configuration files (optional)
│   ├── rules.yaml
│   └── alerts.yaml
│
└── docker/                 # Docker configuration (optional)
    ├── Dockerfile
    └── docker-compose.yml
```

### Core Components

**1. FastAPI Application (`main.py`)**
- Universal proxy route (`/*`)
- Request/response middleware
- Error handling and status codes
- Health check endpoint

**2. Inspection Engine (`waf/inspector.py`)**
- Threat detection logic
- Request normalization
- Pattern matching
- Risk scoring

**3. Rules Engine (`waf/rules.py`)**
- REGEX patterns for detection
- Threat severity levels
- Customizable rule sets
- Easy rule management

**4. Logging System (`waf/logger.py`)**
- JSON and text log formats
- File rotation
- Alert triggers
- Performance metrics

---

##  Security Rules

### Threat Severity Levels

```
 CRITICAL (Score: 90-100)
   Examples: Remote Code Execution (RCE), Advanced SQL Injection
   Action: IMMEDIATE BLOCK + Alert + Notification

 HIGH (Score: 70-89)
   Examples: SQL Injection, XSS, Path Traversal
   Action: BLOCK + Log + Monitor

 MEDIUM (Score: 50-69)
   Examples: Suspicious patterns, Unusual encoding
   Action: LOG + Optional Block + Analysis

 LOW (Score: 1-49)
   Examples: Minor anomalies, Unusual parameters
   Action: LOG only
```

### Detected Attack Patterns

**SQL Injection Patterns:**
```
OR 1=1
UNION SELECT
DROP TABLE
INSERT INTO
DELETE FROM
UPDATE SET
EXEC(
EXECUTE
';--
'/*
*/
```

**XSS Patterns:**
```
<script>
javascript:
onerror=
onload=
onclick=
onmouseover=
<iframe>
<img onerror=
<svg onload=
```

**Path Traversal Patterns:**
```
../
..%2f
..%5c
....//
....\\
..\
/etc/passwd
/etc/shadow
/.env
/config/
/database.yml
```

**Command Injection Patterns:**
```
; command
| command
|| command
& command
&& command
` command `
$( command )
${ command }
> /tmp/file
< /etc/file
```

---

##  API Documentation

### Available Endpoints

#### 1. Universal Proxy Endpoint

```
GET/POST/PUT/DELETE/PATCH /[path]?[params]
Content-Type: application/json (for POST/PUT/PATCH)

Examples:
GET http://localhost:8080/products
POST http://localhost:8080/api/login
GET http://localhost:8080/user/profile?id=123
DELETE http://localhost:8080/items/42
```

**Success Response (SAFE):**
```json
{
  "status": 200,
  "data": { "...": "..." },
  "waf_status": "SAFE",
  "timestamp": "2026-05-06T14:30:45Z"
}
```

**Blocked Response (Attack Detected):**
```json
{
  "status": 403,
  "error": "Forbidden - Potential Security Threat Detected",
  "threat_type": "SQL_INJECTION",
  "blocked_parameter": "id",
  "threat_level": "HIGH",
  "message": "SQL Injection pattern detected in query parameter",
  "timestamp": "2026-05-06T14:30:45Z"
}
```

#### 2. Health Check Endpoint (Optional)

```
GET http://localhost:8080/health

Response:
{
  "status": "healthy",
  "uptime_seconds": 9240,
  "requests_processed": 1234,
  "attacks_blocked": 47,
  "backend_connection": "connected",
  "version": "1.0.0"
}
```

#### 3. Logs API (Optional)

```
GET http://localhost:8080/api/logs?limit=100&severity=HIGH

Response:
{
  "total": 47,
  "limit": 100,
  "logs": [
    {
      "timestamp": "2026-05-06T14:30:45Z",
      "threat_type": "SQL_INJECTION",
      "severity": "HIGH",
      "client_ip": "192.168.1.100"
    }
  ]
}
```

---

##  Contributing

### Types of Contributions

-  New detection rules and patterns
-  Improvement of existing rules
-  Unit tests and integration tests
-  Documentation and tutorials
-  Performance optimizations
-  Bug reports and fixes
-  Feature requests with discussion
-  Security vulnerability reports

### Contribution Process

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/Web-Application-Firewall---Custom-One-.git
   cd Web-Application-Firewall---Custom-One-
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/add-xss-detection-improvement
   ```

3. **Make your changes**
   ```bash
   # Edit files, add tests, update documentation
   ```

4. **Commit with descriptive messages**
   ```bash
   git commit -m "feat: Add detection for encoded XSS payloads"
   git commit -m "test: Add unit tests for new SQL patterns"
   git commit -m "docs: Update README with new rules"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/add-xss-detection-improvement
   ```

6. **Create a Pull Request**
   - Go to GitHub and open a Pull Request
   - Describe changes, testing, and why
   - Link any related issues

### Contribution Guidelines

- **Code Style:** Follow PEP 8 (Python)
- **Comments:** Use English for code comments
- **Testing:** Add tests for new rules
- **Documentation:** Keep README and code comments updated
- **Commits:** Keep commits atomic and descriptive
- **Pull Requests:** One feature per PR
- **Testing:** Run tests before submitting PR

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `perf:` Performance improvement

**Examples:**
```
feat: Add LDAP injection detection

docs: Update installation instructions for Windows

fix: SQL pattern matching case sensitivity issue

test: Add comprehensive XSS payload test cases
```

---

##  Resources

### Official Documentation

- [OWASP Web Security](https://owasp.org/www-community/attacks/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Security Testing Tools

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - Vulnerable web app
- [Burp Suite Community](https://portswigger.net/burp/communitydownload) - Web proxy
- [OWASP ZAP](https://www.zaproxy.org/) - Automated scanner
- [SQLmap](http://sqlmap.org/) - SQL injection tester
- [XSStrike](https://github.com/s0md3v/XSStrike) - XSS detection tool
- [Postman](https://www.postman.com/) - API testing

### Recommended Reading

- *The Web Application Hacker's Handbook* - Stuttard & Pinto
- *Web Security Testing Cookbook* - Stuttard et al.
- [OWASP Testing Guide v4](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)

### Community & Discussion

- [OWASP Community](https://owasp.org/www-community/)
- [PortSwigger Community](https://forum.portswigger.net/)
- [Reddit r/learncsirt](https://www.reddit.com/r/learncsirt/)
- [Reddit r/cybersecurity](https://www.reddit.com/r/cybersecurity/)

---

##  Roadmap

### Phase 1: Core WAF ( Complete)
- [x] Basic FastAPI reverse proxy
- [x] SQL Injection detection
- [x] XSS detection
- [x] Path Traversal detection
- [x] Command Injection detection
- [x] Sensitive file protection
- [x] Request normalization
- [x] File-based logging

### Phase 2: Enhancement ( In Progress)
- [ ] Comprehensive unit tests
- [ ] Rate limiting implementation
- [ ] IP-based GEO-blocking
- [ ] REST API for management
- [ ] Web dashboard for monitoring
- [ ] Performance optimization
- [ ] HTTPS/TLS support

### Phase 3: Advanced Features ( Planned)
- [ ] Machine Learning-based anomaly detection
- [ ] Docker containerization
- [ ] Kubernetes deployment templates
- [ ] SIEM integration (Splunk, ELK Stack)
- [ ] WAF rule management UI
- [ ] Multi-rule set support
- [ ] Custom rule builder

### Phase 4: Enterprise ( Future)
- [ ] Clustering support
- [ ] Load balancing
- [ ] Database integration for rule management
- [ ] Advanced analytics dashboard
- [ ] Threat intelligence feed integration
- [ ] Cloud deployment templates (AWS, Azure, GCP)

---

##  License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

```
MIT License

Copyright (c) 2025 Adam Belbaraka

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

##  Author

**Adam Belbaraka**

- **GitHub:** [@AdamBelbaraka](https://github.com/AdamBelbaraka)
- **Specialization:** Cybersecurity & Penetration Testing
- **Location:** Morocco 🇲🇦
- **Interests:** Offensive security, red teaming, WAF evasion, CTFs

---

##  Acknowledgments

- OWASP team for security resources and guidelines
- FastAPI developers for the excellent framework
- PortSwigger for comprehensive security academy
- The information security community for knowledge sharing
- My Professor Mohy-Eddine Mouad

---

##  Show Your Support

If this project helped you learn about WAF or cybersecurity, please consider:

-  Starring this repository
-  Sharing it with others
-  Providing feedback and suggestions
-  Contributing improvements

---

##  Contact & Support

### Getting Help

| Type | Contact | Response Time |
|------|---------|----------------|
| **Bug Reports** | GitHub Issues | 24-48 hours |
| **Questions** | GitHub Discussions | 24-48 hours |
| **Security** | Email | 24 hours |
| **Contributions** | Pull Request Review | 48-72 hours |


---

##  Project Statistics

- **Lines of Code:** ~500-1000
- **Test Coverage:** In progress
- **Contributors:** 1 (welcome more!)
- **Last Updated:** May 2026
- **Active Development:** Yes 

---

##  Learning Objectives

By studying this project, you will learn:

1.  How reverse proxies work
2.  HTTP request/response processing
3.  Security pattern detection
4.  Async Python with FastAPI
5.  Regular expressions for security
6.  Logging and monitoring
7.  Web application security
8.  OWASP attack vectors

---

**Enjoy learning! Happy hacking! **

---

*Last updated: May 06, 2026*  
*Version: 1.0.0*  
*Status: Active Development *
