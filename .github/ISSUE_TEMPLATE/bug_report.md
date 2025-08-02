---
name: 🐛 Bug Report
about: Report a bug to help us improve AbuseIPDB IOC Enhancement Wrapper
title: "🐛 [Bug]: "
labels: ["bug", "needs-triage"]
assignees: []
---

<!--
🔍 Before submitting, please check if this bug has already been reported!
📖 Search existing issues: https://github.com/JuanVilla424/abuseipdb-ioc/issues
-->

## 🐛 Bug Description

<!-- Provide a clear and concise description of what the bug is -->

## 🔄 Reproduction Steps

<!-- Steps to reproduce the behavior -->

1. **Setup**: <!-- e.g., Created .env file with ABUSEIPDB_API_KEY -->
2. **Command**: <!-- e.g., python -m uvicorn src.main:app -->
3. **Expected**: <!-- e.g., TAXII server started successfully -->
4. **Actual**: <!-- e.g., Connection error to database -->

## 🎯 Expected Behavior

<!-- A clear and concise description of what you expected to happen -->

## 📊 Actual Behavior

<!-- What actually happened? Include error messages, logs, etc. -->

## 📷 Screenshots/Logs

<!-- If applicable, add screenshots or logs to help explain your problem -->

<details>
<summary>📋 Click to expand logs/screenshots</summary>

```
Paste logs here (check logs/langding.log)
```

</details>

## 🖥️ Environment

<!-- Complete this information -->

- **OS**: <!-- e.g., Ubuntu 22.04, Windows 11, macOS 13.0 -->
- **Python Version**: <!-- e.g., 3.11.2 -->
- **AbuseIPDB IOC Version**: <!-- e.g., 1.0.38 -->
- **Database**: <!-- e.g., PostgreSQL 14, Redis 7.0 -->
- **Installation Method**: <!-- docker, pip, git clone, etc. -->

## 📂 Configuration

<!-- If relevant, include your configuration (remove sensitive data!) -->

<details>
<summary>🔧 Configuration Details</summary>

```env
# Your .env or config here (REMOVE API KEYS!)
ABUSEIPDB_API_KEY=*** (REMOVED)
DATABASE_URL=postgresql://user:***@localhost/abuseipdb
REDIS_URL=redis://localhost:6379
TAXII_SERVER_PORT=8080
# Other relevant config
```

</details>

## 🔧 API/Integration Details

<!-- If the bug is related to API or integration issues -->

- **API Endpoint**: <!-- e.g., /taxii2/, /api/v1/iocs -->
- **Integration Type**: <!-- e.g., TAXII 2.1, Elasticsearch CTI, STIX 2.1 -->
- **Request Type**: <!-- e.g., GET, POST -->
- **Error Response**: <!-- Include status code and response body -->

## 🔗 Related Issues

<!-- Link any related issues -->

- Related to: #
- Duplicate of: #

## ✅ Checklist

<!-- Check off completed items -->

- [ ] I have searched existing issues
- [ ] I have included all relevant information
- [ ] I have removed sensitive data (API keys) from logs/config
- [ ] This issue is reproducible
- [ ] I am using the latest version
- [ ] I have checked application logs for detailed errors

## 🏷️ Additional Context

<!-- Add any other context about the problem here -->

---

### 🆘 Need Help?

- 💬 **Community Support**: [GitHub Discussions](https://github.com/JuanVilla424/abuseipdb-ioc/discussions)
- 📚 **Documentation**: [AbuseIPDB IOC Docs](https://github.com/JuanVilla424/abuseipdb-ioc#readme)
- 🔒 **Security Issues**: [Security Policy](https://github.com/JuanVilla424/abuseipdb-ioc/security/policy)

<!-- Thank you for helping improve AbuseIPDB IOC Enhancement Wrapper! 🙏 -->
