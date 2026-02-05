![QuickStrike Banner](assets/banner.txt)

# QuickStrike ⚡

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build: Passing](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/CyberSecPro-95/QuickStrike)

> A hybrid offensive security framework that combines modern API vulnerability detection with classic web application testing for comprehensive security assessments.

## 🎯 Elevator Pitch

QuickStrike is an advanced offensive security framework designed for modern penetration testing and bug bounty programs. It seamlessly integrates API endpoint discovery, authentication bypass testing, IDOR detection, and classic web vulnerability scanning into a unified, high-performance scanning engine.

## ✨ Features

- 🛡️ **Input Sanitization** - Prevents injection attacks with comprehensive validation
- 🏎️ **Adaptive Throttling** - Intelligent rate limiting to avoid detection
- 🔍 **IDOR Detection** - Advanced insecure direct object reference testing
- 🚀 **API Discovery** - Automated endpoint enumeration and validation
- 🔓 **Auth Bypass** - Multi-vector authentication testing
- 🎭 **Token Leakage** - Comprehensive token and session exposure detection
- ⚡ **Classic Web Vulns** - SQLi, XSS, and legacy vulnerability scanning
- 📊 **Professional Reporting** - JSON, Markdown, and PDF output formats
- 🔄 **Escalation Engine** - Automatic attack surface expansion
- 🛑 **Hard Kill** - Immediate shutdown capability for operational security

## 🔒 Responsible Disclosure

QuickStrike is designed **exclusively for authorized security testing**. Users must have explicit permission to test target systems. This tool adheres to industry-standard bug bounty ethics and responsible disclosure practices. Unauthorized use is strictly prohibited and may violate applicable laws.

## 🚀 Quick Start

### Basic Usage
```bash
# Scan with default settings
python3 quickstrike.py -d https://target.com --mode fast

# Silent mode (no verbose output)
python3 quickstrike.py -d https://target.com --mode bounty --silent

# Comprehensive deep scan
python3 quickstrike.py -d https://target.com --mode deep --verbose
```

### Installation
```bash
# Clone the official repository
git clone https://github.com/CyberSecPro-95/QuickStrike.git
cd QuickStrike

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 quickstrike.py -h
```

## 📋 Requirements

- **Python 3.8+** - Core runtime environment
- **curl** - HTTP operations (system dependency)
- **Linux/macOS** - Primary supported platforms

### Optional Dependencies
```bash
# Enhanced features
pip install rich psutil colorama tqdm tabulate

# Async operations
pip install aiofiles aiodns

# Web analysis
pip install httpx wappalyzer dnspython
```

## 🔧 Configuration

QuickStrike supports multiple scanning modes:

- **fast** - Quick reconnaissance and basic vulnerability checks
- **bounty** - Comprehensive bug bounty focused testing  
- **deep** - Full attack surface mapping and escalation

## 📊 Output Formats

- **Console** - Real-time colored output with progress indicators
- **JSON** - Machine-readable results for integration
- **Markdown** - Professional reports for documentation
- **PDF** - Executive summary reports

## 🛡️ Security Features

- **Input Validation** - All user inputs are sanitized and validated
- **Memory Management** - Configurable limits to prevent resource exhaustion
- **Rate Limiting** - Adaptive throttling to avoid detection
- **Safe Execution** - Secure subprocess handling with input validation
- **Audit Logging** - Comprehensive activity tracking

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is developed by **Aryan Akbar Joyia (cybersecpro-95)** and licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

QuickStrike is intended for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before scanning any target. The authors are not responsible for misuse or illegal activities.

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/CyberSecPro-95/QuickStrike/issues)
- **Documentation**: [Wiki](https://github.com/CyberSecPro-95/QuickStrike/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/CyberSecPro-95/QuickStrike/discussions)

---
## 📖 Documentation
For a deep dive into the engineering philosophy and a high-level breakdown of the framework's capabilities, please see the **[Technical Feature Showcase](./FEATURES_EXPLAINED.md)**.


**Made with ❤️ by Aryan Akbar Joyia (cybersecpro-95) for the security community**
