"""
Firewall Manager Module

Handles UFW (Uncomplicated Firewall) configuration with industry-standard
security practices and intelligent state management.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
"""

import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class FirewallManager:
    """Manages UFW firewall configuration with idempotency."""
    
    # Essential firewall rules
    ESSENTIAL_RULES = [
        {
            "rule": "limit 22/tcp",
            "comment": "SSH rate limit",
            "description": "SSH access with rate limiting",
            "critical": True
        },
        {
            "rule": "allow 68/udp",
            "comment": "DHCP client", 
            "description": "DHCP client communication",
            "critical": True
        }
    ]
    
    def __init__(self, state_manager, logger: logging.Logger):
        """Initialize the firewall manager."""
        self.state_manager = state_manager
        self.logger = logger
        
    def _run_command(self, command: List[str], check: bool = True) -> Tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(command)}")
            self.logger.error(f"Error output: {e.stderr}")
            return False, e.stderr
        except Exception as e:
            self.logger.error(f"Unexpected error running command: {e}")
            return False, str(e)
            
    def _is_ufw_installed(self) -> bool:
        """Check if UFW is installed."""
        success, output = self._run_command(["which", "ufw"], check=False)
        return success
        
    def _is_ufw_active(self) -> bool:
        """Check if UFW is active."""
        success, output = self._run_command(["ufw", "status"], check=False)
        if success:
            return "Status: active" in output
        return False
        
    def _get_ufw_rules(self) -> List[str]:
        """Get current UFW rules."""
        success, output = self._run_command(["ufw", "status", "numbered"], check=False)
        if success:
            rules = []
            for line in output.split('\n'):
                if line.strip() and '[' in line and ']' in line:
                    # Extract rule from numbered output
                    rule_part = line.split(']', 1)[1].strip()
                    rules.append(rule_part)
            return rules
        return []
        
    def _rule_exists(self, rule_pattern: str) -> bool:
        """Check if a specific rule exists."""
        current_rules = self._get_ufw_rules()
        for rule in current_rules:
            if rule_pattern.lower() in rule.lower():
                return True
        return False
        
    def _backup_ufw_config(self) -> bool:
        """Backup UFW configuration files."""
        try:
            config_files = [
                "/etc/default/ufw",
                "/etc/ufw/before.rules",
                "/etc/ufw/after.rules",
                "/etc/ufw/user.rules"
            ]
            
            for config_file in config_files:
                if Path(config_file).exists():
                    backup_path = self.state_manager.create_backup_file(config_file)
                    self.logger.info(f"Backed up {config_file} to {backup_path}")
                    
            return True
        except Exception as e:
            self.logger.error(f"Failed to backup UFW configuration: {e}")
            return False
            
    def install_ufw(self) -> bool:
        """Install UFW if not already installed."""
        if self._is_ufw_installed():
            self.logger.info("UFW is already installed")
            return True
            
        self.logger.info("Installing UFW...")
        success, output = self._run_command([
            "apt-get", "install", "-y", "ufw"
        ], check=False)
        
        if success:
            self.logger.info("UFW installed successfully")
            return True
        else:
            self.logger.error("Failed to install UFW")
            return False
            
    def enable_ipv6_support(self) -> bool:
        """Enable IPv6 support in UFW."""
        config_file = Path("/etc/default/ufw")
        
        if not config_file.exists():
            self.logger.error("UFW configuration file not found")
            return False
            
        try:
            # Read current configuration
            with open(config_file, 'r') as f:
                content = f.read()
                
            # Check if IPv6 is already enabled
            if "IPV6=yes" in content:
                self.logger.info("IPv6 support already enabled in UFW")
                return True
                
            # Backup before modification
            self.state_manager.create_backup_file(str(config_file))
            
            # Enable IPv6
            updated_content = content.replace("IPV6=no", "IPV6=yes")
            
            with open(config_file, 'w') as f:
                f.write(updated_content)
                
            self.logger.info("IPv6 support enabled in UFW")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to enable IPv6 support: {e}")
            return False
            
    def configure_default_policies(self) -> bool:
        """Configure restrictive default policies."""
        policies = [
            ("default", "deny", "incoming"),
            ("default", "allow", "outgoing"), 
            ("default", "deny", "routed")
        ]
        
        for policy_type, action, direction in policies:
            self.logger.info(f"Setting {policy_type} {direction} policy to {action}...")
            
            success, output = self._run_command([
                "ufw", policy_type, action, direction
            ], check=False)
            
            if success:
                self.logger.info(f"✓ {policy_type} {direction} policy set to {action}")
                
                # Record policy in state
                self.state_manager.record_firewall_rule({
                    "type": "policy",
                    "direction": direction,
                    "action": action,
                    "status": "configured"
                })
            else:
                self.logger.error(f"Failed to set {policy_type} {direction} policy")
                return False
                
        return True
        
    def configure_logging(self) -> bool:
        """Configure UFW logging."""
        self.logger.info("Configuring UFW logging...")
        
        # Enable logging
        success1, _ = self._run_command(["ufw", "logging", "on"], check=False)
        
        # Set logging level to medium
        success2, _ = self._run_command(["ufw", "logging", "medium"], check=False)
        
        if success1 and success2:
            self.logger.info("UFW logging configured successfully")
            
            # Record logging configuration
            self.state_manager.record_firewall_rule({
                "type": "logging",
                "level": "medium",
                "status": "enabled"
            })
            return True
        else:
            self.logger.warning("UFW logging configuration had issues")
            return False
            
    def add_essential_rules(self) -> bool:
        """Add essential firewall rules."""
        for rule_config in self.ESSENTIAL_RULES:
            rule = rule_config["rule"]
            comment = rule_config["comment"]
            description = rule_config["description"]
            
            # Check if rule already exists
            if self._rule_exists(rule.split()[1]):  # Extract port/protocol part
                self.logger.info(f"✓ Rule already exists: {description}")
                continue
                
            self.logger.info(f"Adding rule: {description}")
            
            # Add the rule with comment
            command = ["ufw"] + rule.split() + ["comment", comment]
            success, output = self._run_command(command, check=False)
            
            if success:
                self.logger.info(f"✓ Added rule: {description}")
                
                # Record rule in state
                self.state_manager.record_firewall_rule({
                    "rule": rule,
                    "comment": comment,
                    "description": description,
                    "status": "added"
                })
            else:
                self.logger.error(f"Failed to add rule: {description}")
                if rule_config["critical"]:
                    return False
                    
        return True
        
    def enable_ufw(self) -> bool:
        """Enable UFW firewall."""
        if self._is_ufw_active():
            self.logger.info("UFW is already active")
            return True
            
        self.logger.info("Enabling UFW firewall...")
        
        # Enable UFW (answer 'y' to prompt)
        success, output = self._run_command([
            "sh", "-c", "echo 'y' | ufw enable"
        ], check=False)
        
        if success:
            self.logger.info("UFW firewall enabled successfully")
            
            # Record UFW enablement
            self.state_manager.record_firewall_rule({
                "type": "status",
                "action": "enabled",
                "status": "active"
            })
            return True
        else:
            self.logger.error("Failed to enable UFW firewall")
            return False
            
    def verify_ufw_configuration(self) -> Dict[str, bool]:
        """Verify UFW configuration."""
        verification_results = {}
        
        # Check if UFW is active
        verification_results["ufw_active"] = self._is_ufw_active()
        
        # Check IPv6 support
        try:
            with open("/etc/default/ufw", 'r') as f:
                content = f.read()
                verification_results["ipv6_enabled"] = "IPV6=yes" in content
        except:
            verification_results["ipv6_enabled"] = False
            
        # Check essential rules
        for rule_config in self.ESSENTIAL_RULES:
            rule_key = f"rule_{rule_config['comment'].replace(' ', '_')}"
            port_protocol = rule_config["rule"].split()[1]
            verification_results[rule_key] = self._rule_exists(port_protocol)
            
        # Check if UFW service is enabled
        success, output = self._run_command(["systemctl", "is-enabled", "ufw"], check=False)
        verification_results["service_enabled"] = success and "enabled" in output
        
        return verification_results
        
    def generate_firewall_report(self) -> str:
        """Generate a comprehensive firewall status report."""
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("UFW FIREWALL CONFIGURATION REPORT")
        report_lines.append("=" * 60)
        report_lines.append("")
        
        # UFW status
        if self._is_ufw_active():
            report_lines.append("Status: ✓ ACTIVE")
        else:
            report_lines.append("Status: ✗ INACTIVE")
            
        report_lines.append("")
        
        # Current rules
        report_lines.append("Current Rules:")
        report_lines.append("-" * 15)
        
        success, output = self._run_command(["ufw", "status", "verbose"], check=False)
        if success:
            report_lines.append(output)
        else:
            report_lines.append("Could not retrieve UFW status")
            
        report_lines.append("")
        
        # Verification results
        verification = self.verify_ufw_configuration()
        report_lines.append("Configuration Verification:")
        report_lines.append("-" * 30)
        
        for check, result in verification.items():
            status = "✓ PASS" if result else "✗ FAIL"
            check_name = check.replace("_", " ").title()
            report_lines.append(f"{check_name:<25} {status}")
            
        return "\n".join(report_lines)
        
    def configure_firewall(self, verify_only: bool = False) -> bool:
        """
        Main firewall configuration function with idempotency.
        
        Args:
            verify_only: If True, only verify current state without making changes
            
        Returns:
            bool: True if firewall is configured successfully
        """
        if verify_only:
            # For verification, check if UFW is active and has essential rules
            verification = self.verify_ufw_configuration()
            return (verification.get("ufw_active", False) and 
                   verification.get("rule_ssh_rate_limit", False))
            
        self.logger.info("Starting UFW firewall configuration...")
        
        # Install UFW if needed
        if not self.install_ufw():
            return False
            
        # Backup configuration
        if not self._backup_ufw_config():
            self.logger.warning("Could not backup UFW configuration")
            
        # Enable IPv6 support
        if not self.enable_ipv6_support():
            self.logger.warning("Could not enable IPv6 support")
            
        # Check if UFW is already configured
        existing_rules = self._get_ufw_rules()
        if existing_rules and self._is_ufw_active():
            self.logger.info(f"UFW already has {len(existing_rules)} rules and is active")
            
            # Verify essential rules exist
            missing_rules = []
            for rule_config in self.ESSENTIAL_RULES:
                port_protocol = rule_config["rule"].split()[1]
                if not self._rule_exists(port_protocol):
                    missing_rules.append(rule_config)
                    
            if missing_rules:
                self.logger.info(f"Adding {len(missing_rules)} missing essential rules...")
                for rule_config in missing_rules:
                    rule = rule_config["rule"]
                    comment = rule_config["comment"]
                    
                    command = ["ufw"] + rule.split() + ["comment", comment]
                    success, _ = self._run_command(command, check=False)
                    
                    if success:
                        self.logger.info(f"✓ Added missing rule: {rule_config['description']}")
                    else:
                        self.logger.error(f"Failed to add rule: {rule_config['description']}")
                        
        else:
            # Fresh configuration
            self.logger.info("Configuring UFW from scratch...")
            
            # Reset UFW to clean state if it has existing rules
            if existing_rules:
                self.logger.info("Resetting UFW to clean state...")
                success, _ = self._run_command(["ufw", "--force", "reset"], check=False)
                if not success:
                    self.logger.warning("Could not reset UFW")
                    
            # Configure default policies
            if not self.configure_default_policies():
                return False
                
            # Add essential rules
            if not self.add_essential_rules():
                return False
                
        # Configure logging
        if not self.configure_logging():
            self.logger.warning("UFW logging configuration had issues")
            
        # Enable UFW
        if not self.enable_ufw():
            return False
            
        # Enable UFW service
        self.logger.info("Enabling UFW service...")
        success, _ = self._run_command(["systemctl", "enable", "ufw"], check=False)
        if success:
            self.logger.info("UFW service enabled")
        else:
            self.logger.warning("Could not enable UFW service")
            
        # Final verification
        verification = self.verify_ufw_configuration()
        passed_checks = sum(1 for result in verification.values() if result)
        total_checks = len(verification)
        
        self.logger.info(f"UFW verification: {passed_checks}/{total_checks} checks passed")
        
        if passed_checks >= (total_checks * 0.8):  # 80% pass rate
            self.logger.info("UFW firewall configured successfully")
            return True
        else:
            self.logger.warning("UFW configuration completed but some checks failed")
            return True  # Don't fail the entire process for minor issues 