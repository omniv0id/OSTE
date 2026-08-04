# 🔍 OSTE - Open Source Tool Evaluator




  Enterprise-grade Open Source Software Risk Assessment Framework


Automatically evaluate open-source software for security, supply chain risks, repository health, licensing, vulnerabilities, and operational trust before adoption.


---

## 📌 Overview

OSTE (Open Source Tool Evaluator) is an automated security assessment framework designed to evaluate open-source software before it is introduced into enterprise environments.

Rather than relying solely on CVEs, OSTE performs a comprehensive assessment by combining repository intelligence, dependency analysis, vulnerability scanning, exploit prediction, malware reputation, licensing validation, and AI-assisted risk scoring into a single actionable report.

The framework generates professional PDF reports that enable security teams, developers, and governance teams to make informed decisions regarding open-source adoption.

---

# 🚀 Features

- Repository Authenticity Assessment
- Repository Activity & Maintenance Analysis
- Contributor Trust Evaluation
- Community Health Analysis
- CVE Detection
- Dependency Vulnerability Analysis
- EPSS Risk Evaluation
- Exploit Availability Assessment
- License Compliance Verification
- Malware & Reputation Checks
- Installation Security Review
- Dynamic AI-Based Risk Scoring
- Executive PDF Report Generation

---

# 🛠 Security Checks Performed

## Repository Intelligence

- Repository age
- Commit history
- Contributor activity
- Release frequency
- Stars & forks analysis
- Issue tracking analysis
- Repository popularity
- Archived/Inactive detection

---

## Vulnerability Analysis

- Direct CVEs
- Vulnerable Dependencies
- Severity Distribution
- CVSS Scores
- EPSS Probability
- Known Exploits

---

## Supply Chain Security

- Dependency Review
- Third-party Risk
- Dependency Age
- Transitive Dependency Analysis
- Download Source Validation

---

## Reputation Analysis

- VirusTotal Reputation
- Hybrid Analysis
- Community Trust
- Malware Indicators

---

## License Analysis

- License Detection
- License Compatibility
- Enterprise Compliance

---

## Installation Security

- Dangerous Installation Scripts
- Suspicious Commands
- Privilege Escalation Risks
- Network Downloads During Installation

---

# 📊 Overall Evaluation Workflow

```
                  User Input
                       │
                       ▼
          Repository / Tool Discovery
                       │
      ┌────────────────┼────────────────┐
      │                │                │
      ▼                ▼                ▼
 Repository      Vulnerability      Reputation
 Analysis          Scanners           Analysis
      │                │                │
      └────────────────┼────────────────┘
                       ▼
              AI Risk Scoring Engine
                       ▼
              Executive PDF Report
```

---

# ⚙ Integrated Security Tools

OSTE integrates multiple security platforms to perform comprehensive evaluations.

| Tool | Purpose |
|------|----------|
| OSV | Open Source Vulnerabilities |
| Semgrep | Static Code Analysis |
| NVD API | CVE Intelligence |
| EPSS API | Exploit Prediction |
| VirusTotal | Reputation Analysis |
| Hybrid Analysis | Malware Intelligence |
| GitHub API | Repository Intelligence |

---

# 📂 Project Structure

```
OSTE/
│
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── docs/
├── images/
├── samples/
├── tests/
├── requirements.txt
└── OSTE.py
```

---

# 📦 Installation

Clone the repository

```bash
git clone https://github.com/<your_username>/OSTE.git
```

Move into the project directory

```bash
cd OSTE
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# ▶ Usage

Evaluate a GitHub repository

```bash
python OSTE.py --url https://github.com/user/repository
```

Evaluate a tool by name

```bash
python OSTE.py --name semgrep
```

Download and evaluate automatically

```bash
python OSTE.py --name semgrep --download yes
```

---

# 📄 Sample Output

The generated report includes:

- Executive Summary
- Overall Risk Score
- Repository Analysis
- CVE Summary
- Dependency Vulnerabilities
- EPSS Assessment
- Malware Reputation
- License Review
- AI Security Assessment
- Final Recommendation

---

# 📈 Risk Scoring

OSTE uses a dynamic scoring engine that evaluates multiple security domains.

The final score is derived from:

- Repository Trust
- Vulnerability Severity
- Dependency Health
- Exploit Likelihood
- Malware Reputation
- License Compliance
- Installation Safety

The overall recommendation is categorized as:

- ✅ Safe
- 🟡 Use with Caution
- 🟠 High Risk
- 🔴 Not Recommended

---

# 🎯 Use Cases

- Enterprise Open Source Adoption
- Secure Software Supply Chain
- Third-Party Risk Assessment
- Security Governance
- Compliance Reviews
- DevSecOps Pipelines
- Procurement Security Validation

---

# 📚 Documentation

Additional documentation is available inside the **docs/** directory.

- Architecture
- Scoring Methodology
- Risk Model
- Installation Guide
- Examples

---

# 🤝 Contributing

Contributions are welcome.

Please read **CONTRIBUTING.md** before submitting issues or pull requests.

---

# 🛡 Security

If you discover a security issue, please refer to **SECURITY.md** for responsible disclosure guidelines.

---



---

# 📜 License

This project is licensed under the MIT License.

See the **LICENSE** file for details.

---

# 👨‍💻 Author

**Mr X**

Security Researcher | Penetration Tester | DevSecOps Enthusiast

---

## ⭐ Support the Project

If you find OSTE useful, consider giving the repository a ⭐ to support future development.

---
