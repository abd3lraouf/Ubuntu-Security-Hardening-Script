"""
Package Manager Module

Handles installation and management of security packages for Ubuntu 24.04 LTS.
Provides intelligent package management with state tracking and idempotency.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
"""

import logging
import subprocess
from typing import Dict, List, Optional, Tuple


class PackageManager:
    """Manages security package installation with idempotency."""
    
    # Critical security packages that must be installed
    CRITICAL_PACKAGES = [
        "ufw",
        "crowdsec", 
        "auditd",
        "apparmor",
        "clamav",
        "aide",
        "unattended-upgrades"
    ]
    
    # Comprehensive security packages for Ubuntu 24.04
    SECURITY_PACKAGES = [
        # File integrity and monitoring
        "aide", "aide-common", "tripwire",
        
        # Auditing and compliance
        "auditd", "audispd-plugins",
        
        # System integrity
        "debsums", "apt-listchanges", "needrestart", "debsecan",
        
        # Access control
        "apparmor", "apparmor-utils", "apparmor-profiles", 
        "apparmor-profiles-extra", "apparmor-notify",
        
        # Antivirus and malware detection
        "clamav", "clamav-daemon", "clamav-freshclam", "clamdscan",
        
        # Automatic updates
        "unattended-upgrades", "update-notifier-common",
        
        # Firewall and network security
        "ufw", "gufw", "arpwatch", "net-tools", "iftop", "tcpdump",
        
        # Intrusion detection/prevention
        "crowdsec", "psad", "snort",
        
        # Rootkit detection
        "rkhunter", "chkrootkit", "unhide",
        
        # Security auditing
        "lynis", "tiger", "nmap",
        
        # Authentication and PAM
        "libpam-pwquality", "libpam-tmpdir", "libpam-apparmor", 
        "libpam-cap", "libpam-modules-bin",
        
        # Cryptography
        "cryptsetup", "cryptsetup-initramfs", "ecryptfs-utils",
        
        # SELinux tools
        "selinux-utils", "selinux-policy-default",
        
        # System monitoring
        "sysstat", "acct",
        
        # Dependencies
        "jq", "curl", "bc",
        
        # Ubuntu 24.04 specific
        "ubuntu-advantage-tools", "systemd-oomd", "systemd-homed",
        
        # OpenSCAP for compliance
        "libopenscap25", "ssg-debian", "ssg-applications"
    ]
    
    def __init__(self, state_manager, logger: logging.Logger):
        """Initialize the package manager."""
        self.state_manager = state_manager
        self.logger = logger
        
    def _run_command(self, command: List[str], check: bool = True) -> Tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check,
                env={"DEBIAN_FRONTEND": "noninteractive"}
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(command)}")
            self.logger.error(f"Error output: {e.stderr}")
            return False, e.stderr
        except Exception as e:
            self.logger.error(f"Unexpected error running command: {e}")
            return False, str(e)
            
    def _is_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed."""
        success, output = self._run_command(["dpkg", "-l", package_name], check=False)
        if success:
            return f"ii  {package_name}" in output
        return False
        
    def _get_package_status(self, package_name: str) -> Dict[str, str]:
        """Get detailed package status."""
        if self._is_package_installed(package_name):
            # Get version info
            success, output = self._run_command(["dpkg", "-s", package_name], check=False)
            if success:
                version = "unknown"
                for line in output.split('\n'):
                    if line.startswith('Version:'):
                        version = line.split(':', 1)[1].strip()
                        break
                        
                return {
                    "status": "installed",
                    "version": version,
                    "method": "dpkg"
                }
            else:
                return {"status": "installed", "version": "unknown", "method": "dpkg"}
        else:
            return {"status": "not_installed"}
            
    def verify_critical_packages(self) -> Tuple[bool, List[str]]:
        """Verify critical packages are installed."""
        self.logger.info("Verifying critical security packages...")
        
        missing_packages = []
        installed_count = 0
        
        for package in self.CRITICAL_PACKAGES:
            if self._is_package_installed(package):
                self.logger.info(f"✓ {package} is installed")
                installed_count += 1
                
                # Record package state
                status = self._get_package_status(package)
                self.state_manager.record_package_state(package, status)
            else:
                self.logger.warning(f"✗ {package} is missing")
                missing_packages.append(package)
                
        self.logger.info(f"Critical packages status: {installed_count}/{len(self.CRITICAL_PACKAGES)} installed")
        
        return len(missing_packages) == 0, missing_packages
        
    def install_package_batch(self, packages: List[str]) -> Tuple[bool, List[str]]:
        """Install packages in batch with error handling."""
        if not packages:
            return True, []
            
        self.logger.info(f"Installing {len(packages)} packages in batch...")
        
        # Attempt batch installation
        command = ["apt-get", "install", "-y"] + packages
        success, output = self._run_command(command, check=False)
        
        if success:
            self.logger.info("Batch installation completed successfully")
            return True, []
        else:
            # Parse failed packages from output
            failed_packages = []
            for line in output.split('\n'):
                if "Unable to locate package" in line:
                    package = line.split()[-1]
                    failed_packages.append(package)
                elif "has no installation candidate" in line:
                    # Extract package name from error message
                    if "Package '" in line and "' has no installation candidate" in line:
                        package = line.split("Package '")[1].split("' has no installation candidate")[0]
                        failed_packages.append(package)
                        
            self.logger.warning(f"Batch installation failed, {len(failed_packages)} packages unavailable")
            return False, failed_packages
            
    def install_package_individual(self, package: str, max_attempts: int = 3) -> bool:
        """Install a single package with retry logic."""
        for attempt in range(1, max_attempts + 1):
            self.logger.info(f"Installing {package} (attempt {attempt}/{max_attempts})...")
            
            success, output = self._run_command(["apt-get", "install", "-y", package], check=False)
            
            if success:
                self.logger.info(f"✓ Successfully installed {package}")
                
                # Record package state
                status = self._get_package_status(package)
                self.state_manager.record_package_state(package, status)
                return True
            else:
                self.logger.warning(f"✗ Failed to install {package} (attempt {attempt}/{max_attempts})")
                if attempt < max_attempts:
                    import time
                    time.sleep(2)  # Brief delay between attempts
                    
        self.logger.error(f"Failed to install {package} after {max_attempts} attempts")
        return False
        
    def install_missing_critical_packages(self, missing_packages: List[str]) -> bool:
        """Install missing critical packages."""
        if not missing_packages:
            return True
            
        self.logger.info(f"Installing {len(missing_packages)} missing critical packages...")
        
        # Try batch installation first
        success, failed_packages = self.install_package_batch(missing_packages)
        
        if success:
            self.logger.info("All missing critical packages installed successfully")
            return True
            
        # Individual installation for failed packages
        if failed_packages:
            self.logger.info(f"Attempting individual installation for {len(failed_packages)} failed packages...")
            
            all_success = True
            for package in failed_packages:
                if not self.install_package_individual(package):
                    if package in self.CRITICAL_PACKAGES:
                        if package == "ufw":
                            self.logger.error("CRITICAL: UFW firewall failed to install")
                            return False
                        else:
                            self.logger.error(f"CRITICAL: Failed to install {package}")
                            all_success = False
                    else:
                        self.logger.warning(f"Non-critical package failed: {package}")
                        
            return all_success
            
        return True
        
    def install_security_packages(self, verify_only: bool = False) -> bool:
        """
        Main package installation function with idempotency.
        
        Args:
            verify_only: If True, only verify current state without making changes
            
        Returns:
            bool: True if packages are installed successfully
        """
        if verify_only:
            # For verification, check critical packages
            all_installed, missing = self.verify_critical_packages()
            return all_installed
            
        self.logger.info("Starting comprehensive security package installation...")
        
        # Remove duplicates and sort packages
        unique_packages = list(set(self.SECURITY_PACKAGES))
        unique_packages.sort()
        
        self.logger.info(f"Total packages to install: {len(unique_packages)}")
        
        # Check which packages are already installed
        already_installed = []
        need_installation = []
        
        for package in unique_packages:
            if self._is_package_installed(package):
                already_installed.append(package)
                # Record existing package state
                status = self._get_package_status(package)
                self.state_manager.record_package_state(package, status)
            else:
                need_installation.append(package)
                
        self.logger.info(f"Already installed: {len(already_installed)} packages")
        self.logger.info(f"Need installation: {len(need_installation)} packages")
        
        if not need_installation:
            self.logger.info("All security packages are already installed")
            return True
            
        # Install packages in batch
        success, failed_packages = self.install_package_batch(need_installation)
        
        # Handle failed packages
        if failed_packages:
            self.logger.warning(f"{len(failed_packages)} packages were not available:")
            for package in failed_packages:
                self.logger.warning(f"  - {package}")
                
            # Remove failed packages from need_installation list
            need_installation = [p for p in need_installation if p not in failed_packages]
            
        # Verify critical packages are installed
        all_critical_installed, missing_critical = self.verify_critical_packages()
        
        if missing_critical:
            if not self.install_missing_critical_packages(missing_critical):
                self.logger.error("Failed to install critical packages")
                return False
                
        # Enable Ubuntu Pro features if available
        self._enable_ubuntu_pro_features()
        
        # Final verification
        final_check, still_missing = self.verify_critical_packages()
        
        if final_check:
            self.logger.info("All critical security packages are installed")
            return True
        else:
            self.logger.error(f"Still missing critical packages: {still_missing}")
            return False
            
    def _enable_ubuntu_pro_features(self) -> None:
        """Enable Ubuntu Pro security features if available."""
        try:
            # Check if pro command exists and is entitled
            success, output = self._run_command(["pro", "status"], check=False)
            
            if success and "entitled" in output.lower():
                self.logger.info("Ubuntu Pro detected, enabling security features...")
                
                # Try to enable USG (Ubuntu Security Guide)
                success_usg, _ = self._run_command(["pro", "enable", "usg"], check=False)
                if success_usg:
                    self.logger.info("✓ Ubuntu Security Guide (USG) enabled")
                else:
                    self.logger.warning("Could not enable USG")
                    
                # Try to enable CIS
                success_cis, _ = self._run_command(["pro", "enable", "cis"], check=False)
                if success_cis:
                    self.logger.info("✓ CIS benchmarks enabled")
                else:
                    self.logger.warning("Could not enable CIS")
            else:
                self.logger.info("Ubuntu Pro not available or not entitled")
                
        except Exception as e:
            self.logger.warning(f"Could not check Ubuntu Pro status: {e}")
            
    def get_package_statistics(self) -> Dict[str, int]:
        """Get package installation statistics."""
        stats = {
            "total_packages": len(self.SECURITY_PACKAGES),
            "critical_packages": len(self.CRITICAL_PACKAGES),
            "installed_packages": 0,
            "missing_packages": 0
        }
        
        for package in self.SECURITY_PACKAGES:
            if self._is_package_installed(package):
                stats["installed_packages"] += 1
            else:
                stats["missing_packages"] += 1
                
        return stats
        
    def generate_package_report(self) -> str:
        """Generate a detailed package installation report."""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("SECURITY PACKAGE INSTALLATION REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        stats = self.get_package_statistics()
        report_lines.append(f"Total Security Packages: {stats['total_packages']}")
        report_lines.append(f"Critical Packages: {stats['critical_packages']}")
        report_lines.append(f"Installed Packages: {stats['installed_packages']}")
        report_lines.append(f"Missing Packages: {stats['missing_packages']}")
        report_lines.append("")
        
        # Critical packages status
        report_lines.append("Critical Packages Status:")
        report_lines.append("-" * 30)
        for package in self.CRITICAL_PACKAGES:
            status = "✓ INSTALLED" if self._is_package_installed(package) else "✗ MISSING"
            report_lines.append(f"{package:<20} {status}")
        report_lines.append("")
        
        # Missing packages
        missing = [p for p in self.SECURITY_PACKAGES if not self._is_package_installed(p)]
        if missing:
            report_lines.append("Missing Packages:")
            report_lines.append("-" * 20)
            for package in missing:
                report_lines.append(f"• {package}")
        else:
            report_lines.append("All security packages are installed!")
            
        return "\n".join(report_lines) 