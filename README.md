# Ubuntu Security Hardening Script - Python Edition

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-orange.svg)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.0-brightgreen.svg)](#)

A comprehensive, idempotent security hardening solution for **Ubuntu 24.04 LTS** written in Python. This script implements industry-standard security practices with intelligent state management and safe re-run capabilities.

## 🚀 Quick Start

### One-Line Installation (Recommended)
```bash
git clone https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script.git && cd Ubuntu-Security-Hardening-Script && sudo python3 setup.py
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script.git
cd Ubuntu-Security-Hardening-Script

# Run the hardening
sudo python3 setup.py
```

### Alternative: Download Individual Files
```bash
# Download setup script (will download other required files automatically)
wget https://raw.githubusercontent.com/abd3lraouf/Ubuntu-Security-Hardening-Script/master/setup.py

# Run setup (downloads modules automatically)
sudo python3 setup.py
```

## 📋 System Requirements

- **Operating System**: Ubuntu 24.04 LTS (Noble Numbat) **ONLY**
- **Python Version**: Python 3.8 or higher
- **Privileges**: Root/sudo access required
- **Disk Space**: Minimum 2GB free space
- **Network**: Internet connection for package downloads

## 🛡️ Security Features

### Core Security Implementations
- **System Updates**: Automated security patches and system updates
- **Package Management**: Installation of 60+ security-focused packages
- **Firewall Configuration**: UFW with restrictive default policies
- **Intrusion Detection**: CrowdSec with community threat intelligence
- **Access Control**: Enhanced SSH and authentication security
- **File Integrity**: AIDE and Tripwire monitoring
- **Antivirus Protection**: ClamAV with real-time scanning
- **Audit Logging**: Comprehensive system auditing with auditd

### Advanced Security Features
- **AppArmor Profiles**: Mandatory access control
- **Rootkit Detection**: Multiple rootkit scanners
- **Network Monitoring**: Advanced network security tools
- **Automatic Updates**: Unattended security updates
- **Compliance Tools**: OpenSCAP and security benchmarks
- **Cryptographic Tools**: Full disk encryption support

## 🏗️ Architecture

### Modular Design
```
ubuntu-hardening/
├── setup.py                    # Main setup and GitHub integration
├── ubuntu_hardening.py         # Main orchestrator
└── modules/
    ├── state_manager.py        # State tracking and idempotency
    ├── system_updates.py       # System package updates
    ├── package_manager.py      # Security package management
    ├── firewall_manager.py     # UFW firewall configuration
    └── crowdsec_manager.py     # CrowdSec installation & config
```

### Key Components
- **State Management**: JSON-based state tracking with backup and recovery
- **Idempotency**: Safe to run multiple times without side effects
- **Error Handling**: Comprehensive error recovery and logging
- **Verification**: Built-in verification and health checks
- **Reporting**: Detailed execution reports and status summaries

## 📖 Usage Examples

### Basic Hardening
```bash
# Full security hardening
sudo python3 ubuntu_hardening.py

# Verification only (no changes)
sudo python3 ubuntu_hardening.py --verify

# Verbose output
sudo python3 ubuntu_hardening.py --verbose

# Force execution without prompts
sudo python3 ubuntu_hardening.py --force
```

### Advanced Usage
```bash
# Check version
python3 ubuntu_hardening.py --version

# Get help
python3 ubuntu_hardening.py --help

# Re-run to update configurations
sudo python3 ubuntu_hardening.py
```

## 🔧 Configuration

### State Management
- **State Directory**: `/var/lib/security-hardening/`
- **Log Directory**: `/var/log/security-hardening/`
- **Backup Directory**: `/var/backups/security-hardening/`

### Key Files
- `hardening-state.json` - Current hardening state
- `hardening-report-*.txt` - Execution reports
- `*.backup-*` - Configuration file backups

## 🚦 Execution Phases

1. **Prerequisites Check** - System validation and requirements
2. **System Updates** - Security patches and system updates
3. **Package Installation** - Security tools and utilities
4. **Firewall Configuration** - UFW setup with restrictive rules
5. **CrowdSec Installation** - Intrusion detection and prevention
6. **Final Verification** - System health and security checks

## 📊 Security Packages Installed

### Critical Security Packages
- **ufw** - Uncomplicated Firewall
- **crowdsec** - Intrusion detection/prevention
- **auditd** - System auditing
- **apparmor** - Mandatory access control
- **clamav** - Antivirus protection
- **aide** - File integrity monitoring
- **unattended-upgrades** - Automatic security updates

### Additional Security Tools (50+ packages)
- File integrity: aide, tripwire, debsums
- Network security: arpwatch, tcpdump, nmap
- Rootkit detection: rkhunter, chkrootkit, unhide
- Security auditing: lynis, tiger
- Encryption: cryptsetup, ecryptfs-utils
- Monitoring: sysstat, acct

## 🔍 Verification & Monitoring

### Built-in Verification
```bash
# Verify current security status
sudo python3 ubuntu_hardening.py --verify
```

### Manual Verification Commands
```bash
# Check firewall status
sudo ufw status verbose

# Check CrowdSec status
sudo systemctl status crowdsec

# View security logs
sudo tail -f /var/log/security-hardening/hardening-*.log

# Check installed security packages
dpkg -l | grep -E "(ufw|crowdsec|auditd|apparmor|clamav)"
```

## 🔄 Idempotency & Re-runs

The script is designed to be **completely idempotent**:

- ✅ Safe to run multiple times
- ✅ Detects previous configurations
- ✅ Only applies missing configurations
- ✅ Preserves custom settings
- ✅ Comprehensive state tracking

### Re-run Scenarios
- **System updates**: Checks for new updates
- **Package verification**: Ensures all security packages are installed
- **Configuration drift**: Detects and corrects configuration changes
- **Service health**: Verifies all security services are running

## ⚠️ Important Safety Information

### Before Running
- 🔐 **Setup SSH key authentication** before running
- 💾 **Create a system backup** or VM snapshot
- 🖥️ **Ensure console access** is available
- 🧪 **Test in non-production** environment first

### After Running
- 🔑 Password authentication will be **disabled**
- 🛡️ Firewall will be **active** with restrictive rules
- 🚫 Some network services may be **blocked**
- 📝 Review the hardening report for details

### Emergency Access
- Console access remains available
- SSH key authentication required
- Recovery instructions in logs
- State files for troubleshooting

## 🐛 Troubleshooting

### Common Issues

**SSH Access Issues**
```bash
# Check SSH configuration
sudo systemctl status ssh
sudo grep -E "(PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config
```

**Firewall Blocking Services**
```bash
# Check UFW rules
sudo ufw status numbered

# Allow specific service (example)
sudo ufw allow 80/tcp comment "HTTP"
```

**CrowdSec Issues**
```bash
# Check CrowdSec status
sudo systemctl status crowdsec
sudo cscli collections list
```

### Recovery Options
- State files: `/var/lib/security-hardening/`
- Configuration backups: `/var/backups/security-hardening/`
- Detailed logs: `/var/log/security-hardening/`
- Emergency markers: `/var/lib/security-hardening/emergency-*`

## 📈 Version History

### Version 5.0 (Current)
- Complete Python rewrite
- Modular architecture
- Enhanced state management
- CrowdSec integration
- Ubuntu 24.04 LTS focus
- GitHub one-liner support

### Previous Versions
- v4.x: Enhanced bash implementation
- v3.x: CrowdSec integration
- v2.x: Improved idempotency
- v1.x: Initial release

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script.git
cd Ubuntu-Security-Hardening-Script

# Test the modules
python3 -c "from modules import *; print('All modules imported successfully')"

# Run syntax checks
python3 -m py_compile ubuntu_hardening.py
python3 -m py_compile setup.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Ubuntu Security Team for security guidelines
- CrowdSec community for threat intelligence
- Open source security community
- Contributors and testers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script/issues)
- **Discussions**: [GitHub Discussions](https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script/discussions)
- **Security**: Please report security issues privately

---

**⚡ Ready to secure your Ubuntu 24.04 LTS system? Use the one-liner installation command above!** 