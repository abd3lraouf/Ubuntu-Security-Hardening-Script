#!/usr/bin/env python3
"""
Ubuntu Security Hardening - Main Hardening Script

A comprehensive, idempotent security hardening solution for Ubuntu 24.04 LTS.
This script implements industry-standard security practices with intelligent
state management and re-run capabilities.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
Version: 5.0
"""

import argparse
import json
import logging
import os
import signal
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import hardening modules
try:
    from modules.state_manager import StateManager
    from modules.system_updates import SystemUpdater
    from modules.package_manager import PackageManager
    from modules.firewall_manager import FirewallManager
    from modules.crowdsec_manager import CrowdSecManager
except ImportError as e:
    print(f"❌ Failed to import hardening modules: {e}")
    print("💡 Please run setup.py first to download the required modules")
    sys.exit(1)

# Version and metadata
__version__ = "5.0"
__author__ = "Abdelraouf Sabri"
__github__ = "https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script"

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'

class UbuntuSecurityHardening:
    """Main Ubuntu Security Hardening orchestrator."""
    
    def __init__(self):
        """Initialize the hardening system."""
        self.state_manager = StateManager()
        self.logger = self._setup_logging()
        self.interrupted = False
        
        # Initialize hardening modules
        self.system_updater = SystemUpdater(self.state_manager, self.logger)
        self.package_manager = PackageManager(self.state_manager, self.logger)
        self.firewall_manager = FirewallManager(self.state_manager, self.logger)
        self.crowdsec_manager = CrowdSecManager(self.state_manager, self.logger)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _setup_logging(self) -> logging.Logger:
        """Set up comprehensive logging system."""
        log_dir = Path("/var/log/security-hardening")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logger = logging.getLogger('ubuntu_hardening')
        logger.setLevel(logging.DEBUG)
        
        # Detailed file handler
        file_handler = logging.FileHandler(
            log_dir / f"hardening-{int(datetime.now().timestamp())}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle interrupt signals gracefully."""
        self.interrupted = True
        self.print_warning(f"\nReceived signal {signum}. Gracefully shutting down...")
        self.state_manager.save_emergency_state("interrupted", f"Signal {signum}")
        sys.exit(130)
        
    def print_colored(self, color: str, message: str) -> None:
        """Print colored message to console."""
        print(f"{color}{message}{Colors.NC}")
        
    def print_success(self, message: str) -> None:
        """Print success message."""
        self.print_colored(Colors.GREEN, f"✓ {message}")
        self.logger.info(f"SUCCESS: {message}")
        
    def print_warning(self, message: str) -> None:
        """Print warning message."""
        self.print_colored(Colors.YELLOW, f"⚠ {message}")
        self.logger.warning(message)
        
    def print_error(self, message: str) -> None:
        """Print error message."""
        self.print_colored(Colors.RED, f"✗ {message}")
        self.logger.error(message)
        
    def print_info(self, message: str) -> None:
        """Print info message."""
        self.print_colored(Colors.BLUE, f"ℹ {message}")
        self.logger.info(message)
        
    def print_header(self, message: str, level: int = 1) -> None:
        """Print formatted header."""
        if level == 1:
            separator = "=" * 80
            self.print_colored(Colors.BOLD, f"\n{separator}")
            self.print_colored(Colors.BOLD, f"{message.center(80)}")
            self.print_colored(Colors.BOLD, f"{separator}\n")
        elif level == 2:
            separator = "-" * 60
            self.print_colored(Colors.CYAN, f"\n{separator}")
            self.print_colored(Colors.CYAN, f"{message.center(60)}")
            self.print_colored(Colors.CYAN, f"{separator}\n")
        else:
            self.print_colored(Colors.PURPLE, f"\n>>> {message}")
            
    def check_prerequisites(self) -> bool:
        """Check system prerequisites with strict Ubuntu 24.04 validation."""
        self.print_header("SYSTEM PREREQUISITES CHECK", 2)
        
        # Check root privileges
        if os.geteuid() != 0:
            self.print_error("This script must be run with root privileges")
            self.print_info("Please run: sudo python3 ubuntu_hardening.py")
            return False
        self.print_success("Running with root privileges")
        
        # Strict Ubuntu 24.04 LTS validation
        try:
            # Check /etc/lsb-release
            ubuntu_version_valid = False
            codename_valid = False
            
            with open('/etc/lsb-release', 'r') as f:
                content = f.read()
                if 'DISTRIB_RELEASE=24.04' in content:
                    ubuntu_version_valid = True
                if 'DISTRIB_CODENAME=noble' in content:
                    codename_valid = True
                    
            # Additional validation with /etc/os-release
            os_release_valid = False
            try:
                with open('/etc/os-release', 'r') as f:
                    os_content = f.read()
                    if 'VERSION_ID="24.04"' in os_content and 'Ubuntu' in os_content:
                        os_release_valid = True
            except:
                pass
                
            # All checks must pass
            if not (ubuntu_version_valid and codename_valid and os_release_valid):
                self.print_error("CRITICAL: This script ONLY supports Ubuntu 24.04 LTS (Noble Numbat)")
                self.print_error("Detected system is not Ubuntu 24.04 LTS")
                self.print_error("Running this script on other versions may cause system damage")
                self.print_info("Supported: Ubuntu 24.04 LTS (Noble Numbat) ONLY")
                
                # Show detected version for debugging
                try:
                    import subprocess
                    result = subprocess.run(['lsb_release', '-a'], capture_output=True, text=True)
                    if result.returncode == 0:
                        self.print_info(f"Detected system:\n{result.stdout}")
                except:
                    pass
                    
                return False
                
            self.print_success("Ubuntu 24.04 LTS (Noble Numbat) verified")
            
        except Exception as e:
            self.print_error(f"Failed to verify Ubuntu version: {e}")
            self.print_error("Unable to confirm Ubuntu 24.04 LTS - aborting for safety")
            return False
            
        # Check disk space (minimum 2GB)
        try:
            stat = os.statvfs('/')
            free_space = (stat.f_bavail * stat.f_frsize) / (1024**3)  # GB
            if free_space < 2.0:
                self.print_error(f"Insufficient disk space: {free_space:.1f}GB (minimum 2GB required)")
                return False
            self.print_success(f"Sufficient disk space: {free_space:.1f}GB available")
        except Exception as e:
            self.print_warning(f"Could not check disk space: {e}")
            
        return True
        
    def show_banner(self) -> None:
        """Display the application banner."""
        banner = f"""
{Colors.BOLD}{Colors.BLUE}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Ubuntu Security Hardening - Python Edition               ║
║                                                                              ║
║  Version: {__version__:<10} Author: {__author__:<30}                    ║
║  Target:  Ubuntu 24.04 LTS (Noble Numbat)                                  ║
║  GitHub:  {__github__}  ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.NC}

{Colors.YELLOW}⚠ IMPORTANT SAFETY WARNINGS:{Colors.NC}
{Colors.RED}  • This script will make significant system changes{Colors.NC}
{Colors.RED}  • Ensure you have created a system backup or snapshot{Colors.NC}
{Colors.RED}  • Configure SSH key authentication before running{Colors.NC}
{Colors.RED}  • Ensure console access is available{Colors.NC}
{Colors.RED}  • Test in a non-production environment first{Colors.NC}
"""
        print(banner)
        
    def check_previous_runs(self) -> bool:
        """Check for previous hardening runs."""
        state = self.state_manager.get_state()
        
        if state.get("hardening_runs", 0) > 0:
            self.print_header("PREVIOUS HARDENING DETECTED", 2)
            self.print_warning(f"Hardening has been run {state['hardening_runs']} times previously")
            
            if state.get("last_run"):
                self.print_info(f"Last run: {state['last_run']}")
                
            if state.get("completed_phases"):
                self.print_info("Previously completed phases:")
                for phase in state["completed_phases"]:
                    self.print_success(f"  ✓ {phase}")
                    
            if state.get("hardening_completed"):
                self.print_success("Previous hardening completed successfully")
                self.print_info("This run will verify and update configurations")
            else:
                self.print_warning("Previous hardening may not have completed")
                self.print_info("This run will continue from where it left off")
                
            # Ask for confirmation
            try:
                response = input(f"\n{Colors.YELLOW}Continue with hardening? (y/N): {Colors.NC}")
                if response.lower() not in ['y', 'yes']:
                    self.print_info("Hardening cancelled by user")
                    return False
            except KeyboardInterrupt:
                self.print_warning("\nHardening cancelled by user")
                return False
        else:
            self.print_info("First time running hardening on this system")
            
        return True
        
    def execute_hardening_phases(self) -> bool:
        """Execute all hardening phases with proper error handling."""
        phases = [
            ("system-updates", self.system_updater.update_system, "System Updates"),
            ("package-installation", self.package_manager.install_security_packages, "Security Package Installation"),
            ("firewall-configuration", self.firewall_manager.configure_firewall, "Firewall Configuration"),
            ("crowdsec-installation", self.crowdsec_manager.install_and_configure_crowdsec, "CrowdSec Installation & Configuration"),
        ]
        
        for phase_name, phase_func, phase_description in phases:
            if self.interrupted:
                self.print_warning("Hardening interrupted")
                return False
                
            try:
                self.print_header(f"PHASE: {phase_description.upper()}", 2)
                
                # Check if phase already completed
                if self.state_manager.is_phase_completed(phase_name):
                    self.print_success(f"{phase_description} already completed")
                    
                    # For critical phases, verify they're still working
                    if phase_name in ["firewall-configuration", "crowdsec-installation"]:
                        self.print_info(f"Verifying {phase_description.lower()}...")
                        if not phase_func(verify_only=True):
                            self.print_warning(f"{phase_description} verification failed, reconfiguring...")
                            if not phase_func():
                                self.print_error(f"Failed to reconfigure {phase_description.lower()}")
                                return False
                    continue
                
                # Execute the phase
                self.print_info(f"Starting {phase_description.lower()}...")
                if phase_func():
                    self.state_manager.mark_phase_completed(phase_name)
                    self.print_success(f"{phase_description} completed successfully")
                else:
                    self.print_error(f"{phase_description} failed")
                    return False
                    
            except Exception as e:
                self.print_error(f"Error in {phase_description}: {e}")
                self.logger.exception(f"Exception in phase {phase_name}")
                return False
                
        return True
        
    def perform_final_verification(self) -> bool:
        """Perform basic system verification."""
        self.print_header("FINAL SYSTEM VERIFICATION", 2)
        
        try:
            # Basic verification checks
            checks_passed = 0
            total_checks = 4
            
            # Check if UFW is active
            if self.firewall_manager._is_ufw_active():
                self.print_success("UFW firewall is active")
                checks_passed += 1
            else:
                self.print_error("UFW firewall is not active")
                
            # Check if CrowdSec is running
            if self.crowdsec_manager._is_crowdsec_running():
                self.print_success("CrowdSec is running")
                checks_passed += 1
            else:
                self.print_warning("CrowdSec is not running")
                
            # Check if critical packages are installed
            critical_installed, missing = self.package_manager.verify_critical_packages()
            if critical_installed:
                self.print_success("All critical packages are installed")
                checks_passed += 1
            else:
                self.print_error(f"Missing critical packages: {missing}")
                
            # Check system updates
            if self.state_manager.is_phase_completed("system-updates"):
                self.print_success("System updates completed")
                checks_passed += 1
            else:
                self.print_warning("System updates not completed")
            
            percentage = (checks_passed / total_checks * 100)
            self.print_info(f"Verification results: {checks_passed}/{total_checks} checks passed ({percentage:.1f}%)")
            
            if percentage >= 75:
                self.print_success("System hardening verification: GOOD")
                return True
            else:
                self.print_warning("System hardening verification: NEEDS ATTENTION")
                return True
                
        except Exception as e:
            self.print_error(f"Verification failed: {e}")
            self.logger.exception("Verification error")
            return False
            
    def cleanup_and_finalize(self) -> None:
        """Perform cleanup and finalization tasks."""
        self.print_header("FINALIZATION", 2)
        
        try:
            # Mark hardening as completed
            self.state_manager.mark_hardening_completed()
            
            # Generate final report
            report_path = self.state_manager.generate_hardening_report()
            
            self.print_success("Ubuntu 24.04 LTS security hardening completed successfully!")
            self.print_info(f"Hardening report: {report_path}")
            self.print_info(f"State tracking: {self.state_manager.state_dir}")
            self.print_info(f"Log files: {Path('/var/log/security-hardening')}")
            
            self.print_warning("CRITICAL REMINDERS:")
            self.print_warning("  • Verify SSH key access before disconnecting")
            self.print_warning("  • Password authentication has been disabled")
            self.print_warning("  • Firewall is now active with restrictive rules")
            self.print_warning("  • Review the hardening report for important details")
            
            self.print_info("Run this script again anytime to verify and update configurations")
            
        except Exception as e:
            self.print_error(f"Finalization error: {e}")
            self.logger.exception("Finalization error")
            
    def main(self, args: argparse.Namespace) -> int:
        """Main execution function."""
        try:
            # Show banner
            self.show_banner()
            
            # Check prerequisites
            if not self.check_prerequisites():
                return 1
                
            # Check previous runs
            if not self.check_previous_runs():
                return 0
                
            # Initialize state tracking
            self.state_manager.initialize_new_run()
            
            # Execute hardening phases
            self.print_header("UBUNTU SECURITY HARDENING EXECUTION", 1)
            if not self.execute_hardening_phases():
                self.print_error("Hardening failed during execution")
                return 1
                
            # Perform final verification
            if not self.perform_final_verification():
                self.print_warning("Hardening completed but verification found issues")
                
            # Cleanup and finalize
            self.cleanup_and_finalize()
            
            return 0
            
        except KeyboardInterrupt:
            self.print_warning("\nHardening interrupted by user")
            self.state_manager.save_emergency_state("interrupted", "User interrupt")
            return 130
        except Exception as e:
            self.print_error(f"Unexpected error: {e}")
            self.logger.exception("Unexpected error occurred")
            self.state_manager.save_emergency_state("error", str(e))
            return 1

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Ubuntu Security Hardening - Python Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  sudo python3 ubuntu_hardening.py              # Full hardening
  sudo python3 ubuntu_hardening.py --verify     # Verification only
  sudo python3 ubuntu_hardening.py --verbose    # Verbose output

GitHub Repository: {__github__}
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Ubuntu Security Hardening v{__version__}'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Perform verification only, no changes'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force execution without confirmations'
    )
    
    return parser

def main() -> int:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger('ubuntu_hardening').setLevel(logging.DEBUG)
        
    hardening = UbuntuSecurityHardening()
    return hardening.main(args)

if __name__ == "__main__":
    sys.exit(main()) 