---
name: 🔒 Security Vulnerability
about: Report a security vulnerability (For serious issues, please use private reporting)
title: "🔒 [Security]: "
labels: ["security", "needs-immediate-attention"]
assignees: ["JuanVilla424"]
---

<!--
🚨 SECURITY NOTICE 🚨

For CRITICAL security vulnerabilities, please DO NOT use public issues!
Instead, use GitHub's private vulnerability reporting:
https://github.com/JuanVilla424/abuseipdb-ioc/security/advisories

This template is for:
- Non-critical security improvements
- Security-related feature requests
- General security discussions
-->

## 🛡️ Security Issue Type

<!-- Select the type of security issue -->

- [ ] 🔓 Vulnerability in dependency
- [ ] 🔐 API key/Authentication issue
- [ ] 📝 Configuration security (.env files)
- [ ] 🌐 Network security (AbuseIPDB API calls)
- [ ] 💾 Data protection (IOC/threat data)
- [ ] 🔍 Information disclosure
- [ ] ⚡ Performance/DoS potential
- [ ] 🛠️ Security tooling improvement
- [ ] 📚 Security documentation
- [ ] Other:

## 🎯 Severity Assessment

<!-- Help us understand the impact -->

- [ ] 🟥 **Critical** - API key exposure, IOC data corruption
- [ ] 🟧 **High** - Threat intelligence exposure, privilege escalation
- [ ] 🟨 **Medium** - Limited IOC exposure, DoS potential
- [ ] 🟩 **Low** - Information disclosure, security hardening
- [ ] 🔵 **Info** - Security best practices, documentation

## 📋 Vulnerability Details

<!-- Provide details about the security issue -->

### 🔍 Description

<!-- Clear description of the security issue -->

### 🎯 Impact

<!-- What could an attacker achieve? -->

### 🔄 Reproduction Steps

<!-- How to reproduce this issue (if safe to share) -->

1. **Setup**: <!-- e.g., Configure .env file -->
2. **Action**: <!-- e.g., Run specific command -->
3. **Result**: <!-- e.g., API key exposed in logs -->

## 🖥️ Affected Components

<!-- Which parts of AbuseIPDB IOC are affected? -->

- [ ] Core IOC processing engine
- [ ] AbuseIPDB API integrations
- [ ] STIX/TAXII processing
- [ ] Elasticsearch CTI integration
- [ ] Database operations (PostgreSQL/Redis)
- [ ] Configuration handling (.env)
- [ ] Logging system
- [ ] Dependencies
- [ ] API endpoints
- [ ] Other:

## 🔧 Environment

- **AbuseIPDB IOC Version**: <!-- e.g., 1.0.38 -->
- **OS**: <!-- e.g., Ubuntu 22.04 -->
- **Python Version**: <!-- e.g., 3.11.2 -->
- **Database**: <!-- PostgreSQL, Redis -->
- **Installation Method**: <!-- pip, git clone -->

## 🔒 IOC/Intelligence Context

<!-- If security issue relates to threat intelligence components -->

- **API Keys Involved**: <!-- Which APIs are affected -->
- **Data Sensitivity**: <!-- What type of IOC data is processed -->
- **Network Exposure**: <!-- External API calls, TAXII feeds -->

## 🛠️ Suggested Fix

<!-- If you have ideas for fixing this issue -->

<details>
<summary>💡 Proposed Solution</summary>

<!-- Your suggestions here -->
<!-- Examples:
- Sanitize IOC data in logs
- Secure API key storage
- Validate STIX input
- Add rate limiting
-->

</details>

## 📚 References

<!-- Security advisories, CVEs, documentation -->

- CVE:
- Related Security Advisory:
- OWASP References:
- Python Security Guidelines:
- STIX/TAXII Security Guidelines:
- Other:

## ✅ Security Checklist

- [ ] I have assessed the severity appropriately
- [ ] I have NOT included sensitive exploitation details
- [ ] This is appropriate for public disclosure
- [ ] I have checked for existing security reports
- [ ] I understand this will be publicly visible
- [ ] I have considered the impact on threat intelligence integrations

---

### 🔒 Security Resources

- **Private Reporting**: [GitHub Security Advisories](https://github.com/JuanVilla424/abuseipdb-ioc/security/advisories)
- **Security Policy**: [SECURITY.md](https://github.com/JuanVilla424/abuseipdb-ioc/blob/main/SECURITY.md)
- **Contact**: For urgent issues, contact r6ty5r296it6tl4eg5m.constant214@passinbox.com

<!-- Thank you for helping keep AbuseIPDB IOC secure! 🙏 -->
