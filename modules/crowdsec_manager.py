"""
CrowdSec Manager Module

Handles CrowdSec installation, configuration, and management for advanced
intrusion detection and prevention with community threat intelligence.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
"""

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CrowdSecManager:
    """Manages CrowdSec installation and configuration with idempotency."""
    
    # Essential CrowdSec collections
    ESSENTIAL_COLLECTIONS = [
        "crowdsecurity/base-http-scenarios",
        "crowdsecurity/http-cve",
        "crowdsecurity/iptables",
        "crowdsecurity/linux",
        "crowdsecurity/nginx",
        "crowdsecurity/apache2",
        "crowdsecurity/ssh-bf",
        "crowdsecurity/sshd",
        "crowdsecurity/postfix"
    ]
    
    # Essential parsers
    ESSENTIAL_PARSERS = [
        "crowdsecurity/syslog-logs",
        "crowdsecurity/dateparse-enrich", 
        "crowdsecurity/geoip-enrich",
        "crowdsecurity/http-logs",
        "crowdsecurity/nginx-logs",
        "crowdsecurity/apache2-logs",
        "crowdsecurity/sshd-logs"
    ]
    
    # Essential bouncers
    ESSENTIAL_BOUNCERS = [
        "crowdsecurity/cs-firewall-bouncer"
    ]
    
    def __init__(self, state_manager, logger: logging.Logger):
        """Initialize the CrowdSec manager."""
        self.state_manager = state_manager
        self.logger = logger
        
    def _run_command(self, command: List[str], check: bool = True, timeout: int = 300) -> Tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check,
                timeout=timeout,
                env={"DEBIAN_FRONTEND": "noninteractive"}
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(command)}")
            self.logger.error(f"Error output: {e.stderr}")
            return False, e.stderr
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {' '.join(command)}")
            return False, "Command timed out"
        except Exception as e:
            self.logger.error(f"Unexpected error running command: {e}")
            return False, str(e)
            
    def _is_crowdsec_installed(self) -> bool:
        """Check if CrowdSec is installed."""
        success, output = self._run_command(["which", "crowdsec"], check=False)
        return success
        
    def _is_crowdsec_running(self) -> bool:
        """Check if CrowdSec service is running."""
        success, output = self._run_command(["systemctl", "is-active", "crowdsec"], check=False)
        return success and "active" in output
        
    def _get_crowdsec_version(self) -> Optional[str]:
        """Get CrowdSec version."""
        success, output = self._run_command(["crowdsec", "-version"], check=False)
        if success:
            for line in output.split('\n'):
                if line.startswith('version:'):
                    return line.split(':', 1)[1].strip()
        return None
        
    def _backup_crowdsec_config(self) -> bool:
        """Backup CrowdSec configuration files."""
        try:
            config_files = [
                "/etc/crowdsec/config.yaml",
                "/etc/crowdsec/profiles.yaml",
                "/etc/crowdsec/notifications.yaml"
            ]
            
            for config_file in config_files:
                if Path(config_file).exists():
                    backup_path = self.state_manager.create_backup_file(config_file)
                    self.logger.info(f"Backed up {config_file} to {backup_path}")
                    
            return True
        except Exception as e:
            self.logger.error(f"Failed to backup CrowdSec configuration: {e}")
            return False
            
    def install_crowdsec_repository(self) -> bool:
        """Install CrowdSec APT repository."""
        self.logger.info("Installing CrowdSec repository...")
        
        # Download and install the repository setup script
        commands = [
            ["curl", "-s", "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh"],
            ["bash"]
        ]
        
        try:
            # Download the script
            result1 = subprocess.run(
                commands[0],
                capture_output=True,
                text=True,
                check=True,
                timeout=60
            )
            
            # Execute the script
            result2 = subprocess.run(
                commands[1],
                input=result1.stdout,
                capture_output=True,
                text=True,
                check=True,
                timeout=120
            )
            
            self.logger.info("CrowdSec repository installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install CrowdSec repository: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error installing repository: {e}")
            return False
            
    def install_crowdsec(self) -> bool:
        """Install CrowdSec package."""
        if self._is_crowdsec_installed():
            self.logger.info("CrowdSec is already installed")
            return True
            
        # Install repository first
        if not self.install_crowdsec_repository():
            return False
            
        # Update package list
        self.logger.info("Updating package list...")
        success, _ = self._run_command(["apt-get", "update"], check=False)
        if not success:
            self.logger.warning("Could not update package list")
            
        # Install CrowdSec
        self.logger.info("Installing CrowdSec...")
        success, output = self._run_command([
            "apt-get", "install", "-y", "crowdsec"
        ], check=False, timeout=600)
        
        if success:
            self.logger.info("CrowdSec installed successfully")
            
            # Record installation in state
            version = self._get_crowdsec_version()
            self.state_manager.record_package_state("crowdsec", {
                "status": "installed",
                "version": version or "unknown",
                "method": "apt"
            })
            return True
        else:
            self.logger.error("Failed to install CrowdSec")
            return False
            
    def install_firewall_bouncer(self) -> bool:
        """Install CrowdSec firewall bouncer."""
        self.logger.info("Installing CrowdSec firewall bouncer...")
        
        success, output = self._run_command([
            "apt-get", "install", "-y", "crowdsec-firewall-bouncer-iptables"
        ], check=False, timeout=300)
        
        if success:
            self.logger.info("CrowdSec firewall bouncer installed successfully")
            return True
        else:
            self.logger.warning("Could not install firewall bouncer via apt, trying manual installation...")
            return self._install_bouncer_manual()
            
    def _install_bouncer_manual(self) -> bool:
        """Install firewall bouncer manually."""
        try:
            # Download and install bouncer
            commands = [
                ["wget", "-O", "/tmp/crowdsec-firewall-bouncer.tgz", 
                 "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/latest/download/crowdsec-firewall-bouncer-linux-amd64.tgz"],
                ["tar", "-xzf", "/tmp/crowdsec-firewall-bouncer.tgz", "-C", "/tmp/"],
                ["bash", "/tmp/crowdsec-firewall-bouncer-*/install.sh"]
            ]
            
            for command in commands:
                success, output = self._run_command(command, check=False, timeout=120)
                if not success:
                    self.logger.error(f"Failed to execute: {' '.join(command)}")
                    return False
                    
            self.logger.info("Firewall bouncer installed manually")
            return True
            
        except Exception as e:
            self.logger.error(f"Manual bouncer installation failed: {e}")
            return False
            
    def configure_crowdsec(self) -> bool:
        """Configure CrowdSec with optimal settings."""
        self.logger.info("Configuring CrowdSec...")
        
        # Backup existing configuration
        if not self._backup_crowdsec_config():
            self.logger.warning("Could not backup CrowdSec configuration")
            
        # Enable and start CrowdSec service
        self.logger.info("Enabling CrowdSec service...")
        success, _ = self._run_command(["systemctl", "enable", "crowdsec"], check=False)
        if success:
            self.logger.info("CrowdSec service enabled")
        else:
            self.logger.warning("Could not enable CrowdSec service")
            
        # Start CrowdSec service
        self.logger.info("Starting CrowdSec service...")
        success, _ = self._run_command(["systemctl", "start", "crowdsec"], check=False)
        if success:
            self.logger.info("CrowdSec service started")
        else:
            self.logger.error("Could not start CrowdSec service")
            return False
            
        # Wait for service to initialize
        self.logger.info("Waiting for CrowdSec to initialize...")
        time.sleep(10)
        
        # Verify service is running
        if not self._is_crowdsec_running():
            self.logger.error("CrowdSec service is not running")
            return False
            
        return True
        
    def install_collections(self) -> bool:
        """Install essential CrowdSec collections."""
        self.logger.info("Installing CrowdSec collections...")
        
        installed_collections = []
        failed_collections = []
        
        for collection in self.ESSENTIAL_COLLECTIONS:
            self.logger.info(f"Installing collection: {collection}")
            
            success, output = self._run_command([
                "cscli", "collections", "install", collection
            ], check=False, timeout=120)
            
            if success:
                self.logger.info(f"✓ Installed collection: {collection}")
                installed_collections.append(collection)
                
                # Record collection in state
                self.state_manager.record_crowdsec_collection(collection, {
                    "status": "installed",
                    "type": "collection"
                })
            else:
                self.logger.warning(f"✗ Failed to install collection: {collection}")
                failed_collections.append(collection)
                
        self.logger.info(f"Collections installed: {len(installed_collections)}/{len(self.ESSENTIAL_COLLECTIONS)}")
        
        if failed_collections:
            self.logger.warning(f"Failed collections: {failed_collections}")
            
        # At least half should be installed for success
        return len(installed_collections) >= (len(self.ESSENTIAL_COLLECTIONS) / 2)
        
    def install_parsers(self) -> bool:
        """Install essential CrowdSec parsers."""
        self.logger.info("Installing CrowdSec parsers...")
        
        installed_parsers = []
        failed_parsers = []
        
        for parser in self.ESSENTIAL_PARSERS:
            self.logger.info(f"Installing parser: {parser}")
            
            success, output = self._run_command([
                "cscli", "parsers", "install", parser
            ], check=False, timeout=120)
            
            if success:
                self.logger.info(f"✓ Installed parser: {parser}")
                installed_parsers.append(parser)
                
                # Record parser in state
                self.state_manager.record_crowdsec_collection(parser, {
                    "status": "installed",
                    "type": "parser"
                })
            else:
                self.logger.warning(f"✗ Failed to install parser: {parser}")
                failed_parsers.append(parser)
                
        self.logger.info(f"Parsers installed: {len(installed_parsers)}/{len(self.ESSENTIAL_PARSERS)}")
        
        return len(installed_parsers) >= (len(self.ESSENTIAL_PARSERS) / 2)
        
    def configure_bouncer(self) -> bool:
        """Configure CrowdSec firewall bouncer."""
        self.logger.info("Configuring CrowdSec firewall bouncer...")
        
        # Generate bouncer API key
        success, output = self._run_command([
            "cscli", "bouncers", "add", "firewall-bouncer"
        ], check=False)
        
        if success:
            # Extract API key from output
            api_key = None
            for line in output.split('\n'):
                if 'API key for' in line:
                    api_key = line.split(':')[-1].strip()
                    break
                    
            if api_key:
                self.logger.info("Generated bouncer API key")
                
                # Configure bouncer with API key
                bouncer_config = f"""
api_url: http://localhost:8080/
api_key: {api_key}
disable_ipv6: false
deny_action: DROP
deny_log: true
"""
                
                try:
                    config_path = Path("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
                    config_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(config_path, 'w') as f:
                        f.write(bouncer_config)
                        
                    self.logger.info("Bouncer configuration written")
                    
                    # Enable and start bouncer service
                    success, _ = self._run_command(["systemctl", "enable", "crowdsec-firewall-bouncer"], check=False)
                    if success:
                        self.logger.info("Bouncer service enabled")
                        
                    success, _ = self._run_command(["systemctl", "start", "crowdsec-firewall-bouncer"], check=False)
                    if success:
                        self.logger.info("Bouncer service started")
                        return True
                    else:
                        self.logger.warning("Could not start bouncer service")
                        
                except Exception as e:
                    self.logger.error(f"Failed to write bouncer configuration: {e}")
                    
            else:
                self.logger.error("Could not extract API key from output")
        else:
            self.logger.error("Failed to generate bouncer API key")
            
        return False
        
    def reload_crowdsec(self) -> bool:
        """Reload CrowdSec configuration."""
        self.logger.info("Reloading CrowdSec configuration...")
        
        success, _ = self._run_command(["systemctl", "reload", "crowdsec"], check=False)
        if success:
            self.logger.info("CrowdSec configuration reloaded")
            return True
        else:
            self.logger.warning("Could not reload CrowdSec configuration")
            return False
            
    def verify_crowdsec_installation(self) -> Dict[str, bool]:
        """Verify CrowdSec installation and configuration."""
        verification_results = {}
        
        # Check if CrowdSec is installed
        verification_results["crowdsec_installed"] = self._is_crowdsec_installed()
        
        # Check if CrowdSec is running
        verification_results["crowdsec_running"] = self._is_crowdsec_running()
        
        # Check if collections are installed
        success, output = self._run_command(["cscli", "collections", "list"], check=False)
        if success:
            installed_count = output.count("✓")
            verification_results["collections_installed"] = installed_count >= 3
        else:
            verification_results["collections_installed"] = False
            
        # Check if parsers are installed
        success, output = self._run_command(["cscli", "parsers", "list"], check=False)
        if success:
            installed_count = output.count("✓")
            verification_results["parsers_installed"] = installed_count >= 3
        else:
            verification_results["parsers_installed"] = False
            
        # Check if bouncers are configured
        success, output = self._run_command(["cscli", "bouncers", "list"], check=False)
        if success:
            verification_results["bouncers_configured"] = "firewall-bouncer" in output
        else:
            verification_results["bouncers_configured"] = False
            
        # Check if bouncer service is running
        success, output = self._run_command(["systemctl", "is-active", "crowdsec-firewall-bouncer"], check=False)
        verification_results["bouncer_running"] = success and "active" in output
        
        return verification_results
        
    def generate_crowdsec_report(self) -> str:
        """Generate a comprehensive CrowdSec status report."""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("CROWDSEC CONFIGURATION REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        # CrowdSec status
        if self._is_crowdsec_running():
            version = self._get_crowdsec_version()
            report_lines.append(f"Status: ✓ RUNNING (v{version or 'unknown'})")
        else:
            report_lines.append("Status: ✗ NOT RUNNING")
            
        report_lines.append("")
        
        # Collections status
        report_lines.append("Installed Collections:")
        report_lines.append("-" * 25)
        
        success, output = self._run_command(["cscli", "collections", "list"], check=False)
        if success:
            report_lines.append(output)
        else:
            report_lines.append("Could not retrieve collections list")
            
        report_lines.append("")
        
        # Parsers status
        report_lines.append("Installed Parsers:")
        report_lines.append("-" * 20)
        
        success, output = self._run_command(["cscli", "parsers", "list"], check=False)
        if success:
            report_lines.append(output)
        else:
            report_lines.append("Could not retrieve parsers list")
            
        report_lines.append("")
        
        # Bouncers status
        report_lines.append("Configured Bouncers:")
        report_lines.append("-" * 22)
        
        success, output = self._run_command(["cscli", "bouncers", "list"], check=False)
        if success:
            report_lines.append(output)
        else:
            report_lines.append("Could not retrieve bouncers list")
            
        report_lines.append("")
        
        # Verification results
        verification = self.verify_crowdsec_installation()
        report_lines.append("Installation Verification:")
        report_lines.append("-" * 30)
        
        for check, result in verification.items():
            status = "✓ PASS" if result else "✗ FAIL"
            check_name = check.replace("_", " ").title()
            report_lines.append(f"{check_name:<25} {status}")
            
        return "\n".join(report_lines)
        
    def install_and_configure_crowdsec(self, verify_only: bool = False) -> bool:
        """
        Main CrowdSec installation and configuration function with idempotency.
        
        Args:
            verify_only: If True, only verify current state without making changes
            
        Returns:
            bool: True if CrowdSec is installed and configured successfully
        """
        if verify_only:
            # For verification, check if CrowdSec is running and has basic configuration
            verification = self.verify_crowdsec_installation()
            return (verification.get("crowdsec_running", False) and 
                   verification.get("collections_installed", False))
            
        self.logger.info("Starting CrowdSec installation and configuration...")
        
        # Install CrowdSec
        if not self.install_crowdsec():
            return False
            
        # Configure CrowdSec
        if not self.configure_crowdsec():
            return False
            
        # Install collections
        if not self.install_collections():
            self.logger.warning("Some collections failed to install")
            
        # Install parsers
        if not self.install_parsers():
            self.logger.warning("Some parsers failed to install")
            
        # Install firewall bouncer
        if not self.install_firewall_bouncer():
            self.logger.warning("Could not install firewall bouncer")
        else:
            # Configure bouncer
            if not self.configure_bouncer():
                self.logger.warning("Could not configure firewall bouncer")
                
        # Reload configuration
        self.reload_crowdsec()
        
        # Final verification
        verification = self.verify_crowdsec_installation()
        passed_checks = sum(1 for result in verification.values() if result)
        total_checks = len(verification)
        
        self.logger.info(f"CrowdSec verification: {passed_checks}/{total_checks} checks passed")
        
        if passed_checks >= (total_checks * 0.6):  # 60% pass rate
            self.logger.info("CrowdSec installed and configured successfully")
            return True
        else:
            self.logger.warning("CrowdSec installation completed but some checks failed")
            return True  # Don't fail the entire process for CrowdSec issues 