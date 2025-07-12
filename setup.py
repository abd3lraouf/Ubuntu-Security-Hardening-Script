#!/usr/bin/env python3
"""
Ubuntu Security Hardening - Python Setup Script

A modern, idempotent security hardening solution for Ubuntu 24.04 LTS.
This script provides comprehensive security hardening with state tracking
and intelligent re-run capabilities.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
Version: 5.0
"""

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error

# Version and metadata
__version__ = "5.0"
__author__ = "Abdelraouf Sabri"
__github__ = "https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script"

# Color codes for enhanced output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

@dataclass
class SystemInfo:
    """System information container."""
    ubuntu_version: str
    codename: str
    architecture: str
    kernel: str
    is_supported: bool

class SecurityHardeningSetup:
    """Main setup class for Ubuntu Security Hardening."""
    
    SUPPORTED_UBUNTU_VERSION = "24.04"
    GITHUB_RAW_BASE = "https://raw.githubusercontent.com/abd3lraouf/Ubuntu-Security-Hardening-Script/master"
    STATE_DIR = Path("/var/lib/security-hardening")
    LOG_DIR = Path("/var/log/security-hardening")
    
    def __init__(self):
        """Initialize the setup system."""
        self.system_info: Optional[SystemInfo] = None
        self.logger = self._setup_logging()
        self.state_file = self.STATE_DIR / "setup-state.json"
        
    def _setup_logging(self) -> logging.Logger:
        """Set up comprehensive logging system."""
        # Create log directory
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Configure logger
        logger = logging.getLogger('ubuntu_hardening')
        logger.setLevel(logging.DEBUG)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        simple_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File handler for debug logs
        debug_handler = logging.FileHandler(self.LOG_DIR / f"setup-debug-{int(time.time())}.log")
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(detailed_formatter)
        
        # File handler for general logs
        info_handler = logging.FileHandler(self.LOG_DIR / f"setup-{int(time.time())}.log")
        info_handler.setLevel(logging.INFO)
        info_handler.setFormatter(simple_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        
        logger.addHandler(debug_handler)
        logger.addHandler(info_handler)
        logger.addHandler(console_handler)
        
        return logger
    
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
            
    def check_root_privileges(self) -> bool:
        """Check if running with root privileges."""
        if os.geteuid() != 0:
            self.print_error("This script must be run with root privileges")
            self.print_info("Please run: sudo python3 setup.py")
            return False
        self.print_success("Running with root privileges")
        return True
        
    def detect_system_info(self) -> SystemInfo:
        """Detect Ubuntu system information."""
        try:
            # Get Ubuntu version info
            with open('/etc/lsb-release', 'r') as f:
                lsb_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        lsb_info[key] = value.strip('"')
            
            version = lsb_info.get('DISTRIB_RELEASE', 'unknown')
            codename = lsb_info.get('DISTRIB_CODENAME', 'unknown')
            
            # Get system info
            architecture = platform.machine()
            kernel = platform.release()
            
            # Check if supported
            is_supported = version == self.SUPPORTED_UBUNTU_VERSION
            
            system_info = SystemInfo(
                ubuntu_version=version,
                codename=codename,
                architecture=architecture,
                kernel=kernel,
                is_supported=is_supported
            )
            
            self.logger.debug(f"Detected system: {system_info}")
            return system_info
            
        except Exception as e:
            self.logger.error(f"Failed to detect system info: {e}")
            raise
            
    def validate_ubuntu_version(self) -> bool:
        """Strict validation for Ubuntu 24.04 LTS only."""
        self.print_header("UBUNTU VERSION VALIDATION", 2)
        
        self.system_info = self.detect_system_info()
        
        self.print_info(f"Detected: Ubuntu {self.system_info.ubuntu_version} ({self.system_info.codename})")
        self.print_info(f"Architecture: {self.system_info.architecture}")
        self.print_info(f"Kernel: {self.system_info.kernel}")
        
        # Strict validation for Ubuntu 24.04 LTS only
        if not self.system_info.is_supported or self.system_info.codename != 'noble':
            self.print_error("CRITICAL: This script ONLY supports Ubuntu 24.04 LTS (Noble Numbat)")
            self.print_error(f"Detected: Ubuntu {self.system_info.ubuntu_version} ({self.system_info.codename})")
            self.print_error("Running this script on other Ubuntu versions is NOT supported")
            self.print_error("and may cause system instability or damage")
            
            # Show additional system info for debugging
            try:
                import subprocess
                result = subprocess.run(['lsb_release', '-a'], capture_output=True, text=True)
                if result.returncode == 0:
                    self.print_info(f"Complete system information:\n{result.stdout}")
            except:
                pass
                
            self.print_info("Please use Ubuntu 24.04 LTS (Noble Numbat) ONLY")
            return False
        
        self.print_success(f"Ubuntu {self.system_info.ubuntu_version} LTS (Noble Numbat) verified")
        self.print_success("System meets all requirements - proceeding with hardening")
        return True
            
    def check_internet_connectivity(self) -> bool:
        """Check internet connectivity for downloading files."""
        try:
            self.print_info("Checking internet connectivity...")
            urllib.request.urlopen('https://github.com', timeout=10)
            self.print_success("Internet connectivity verified")
            return True
        except urllib.error.URLError:
            self.print_error("No internet connectivity detected")
            self.print_info("Internet access is required to download the latest hardening scripts")
            return False
            
    def download_file(self, url: str, destination: Path) -> bool:
        """Download file from GitHub repository."""
        try:
            self.print_info(f"Downloading: {url.split('/')[-1]}")
            
            with urllib.request.urlopen(url) as response:
                content = response.read()
                
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            with open(destination, 'wb') as f:
                f.write(content)
                
            # Make executable if it's a Python script
            if destination.suffix == '.py':
                destination.chmod(0o755)
                
            self.print_success(f"Downloaded: {destination.name}")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to download {url}: {e}")
            return False
            
    def download_hardening_files(self) -> bool:
        """Download the latest hardening files from GitHub."""
        self.print_header("DOWNLOADING LATEST HARDENING FILES", 2)
        
        files_to_download = [
            ("ubuntu_hardening.py", "ubuntu_hardening.py"),
            ("modules/__init__.py", "modules/__init__.py"),
            ("modules/system_updates.py", "modules/system_updates.py"),
            ("modules/package_manager.py", "modules/package_manager.py"),
            ("modules/firewall_manager.py", "modules/firewall_manager.py"),
            ("modules/crowdsec_manager.py", "modules/crowdsec_manager.py"),
            ("modules/state_manager.py", "modules/state_manager.py"),
        ]
        
        success_count = 0
        for github_path, local_path in files_to_download:
            url = f"{self.GITHUB_RAW_BASE}/{github_path}"
            destination = Path(local_path)
            
            if self.download_file(url, destination):
                success_count += 1
            else:
                self.print_warning(f"Skipping {local_path} - download failed")
                
        if success_count >= 2:  # At least main script and one module
            self.print_success(f"Downloaded {success_count}/{len(files_to_download)} files")
            return True
        else:
            self.print_error("Failed to download essential hardening files")
            return False
            
    def load_state(self) -> Dict:
        """Load state from JSON file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load state: {e}")
                
        return {
            "version": __version__,
            "setup_runs": 0,
            "last_run": None,
            "hardening_completed": False,
            "files_downloaded": False
        }
        
    def save_state(self, state: Dict) -> None:
        """Save state to JSON file."""
        try:
            self.STATE_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
            self.state_file.chmod(0o600)
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
            
    def check_previous_setup(self) -> Dict:
        """Check for previous setup runs."""
        state = self.load_state()
        
        if state["setup_runs"] > 0:
            self.print_header("PREVIOUS SETUP DETECTED", 2)
            self.print_warning(f"Setup has been run {state['setup_runs']} times previously")
            
            if state["last_run"]:
                self.print_info(f"Last run: {state['last_run']}")
                
            if state["files_downloaded"]:
                self.print_success("Hardening files previously downloaded")
            else:
                self.print_info("Hardening files need to be downloaded")
                
            if state["hardening_completed"]:
                self.print_success("System hardening previously completed")
                self.print_info("Re-running will verify and update configurations")
            else:
                self.print_info("System hardening not yet completed")
                
        return state
        
    def run_hardening_script(self) -> bool:
        """Execute the main hardening script."""
        self.print_header("EXECUTING UBUNTU SECURITY HARDENING", 1)
        
        hardening_script = Path("ubuntu_hardening.py")
        
        if not hardening_script.exists():
            self.print_error("Hardening script not found")
            return False
            
        try:
            self.print_info("Starting Ubuntu 24.04 LTS security hardening...")
            self.print_warning("IMPORTANT: Ensure you have:")
            self.print_warning("  • Created a system backup or snapshot")
            self.print_warning("  • Configured SSH key authentication")
            self.print_warning("  • Console access available")
            
            # Execute the hardening script
            result = subprocess.run([
                sys.executable, str(hardening_script)
            ], capture_output=False, text=True)
            
            if result.returncode == 0:
                self.print_success("Ubuntu security hardening completed successfully!")
                return True
            else:
                self.print_error("Security hardening failed")
                return False
                
        except Exception as e:
            self.print_error(f"Failed to execute hardening script: {e}")
            return False
            
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
"""
        print(banner)
        
    def main(self, args: argparse.Namespace) -> int:
        """Main execution function."""
        try:
            # Show banner
            self.show_banner()
            
            # Check root privileges
            if not self.check_root_privileges():
                return 1
                
            # Validate Ubuntu version
            if not self.validate_ubuntu_version():
                return 1
                
            # Check internet connectivity
            if not self.check_internet_connectivity():
                return 1
                
            # Check previous setup runs
            state = self.check_previous_setup()
            
            # Update state
            state["setup_runs"] += 1
            state["last_run"] = datetime.now().isoformat()
            
            # Download latest files unless using local
            if not args.local:
                if self.download_hardening_files():
                    state["files_downloaded"] = True
                else:
                    self.print_error("Failed to download hardening files")
                    return 1
            else:
                self.print_info("Using local hardening files (--local flag)")
                
            # Save state
            self.save_state(state)
            
            # Execute hardening if not in download-only mode
            if not args.download_only:
                if self.run_hardening_script():
                    state["hardening_completed"] = True
                    self.save_state(state)
                    
                    self.print_header("SETUP COMPLETED SUCCESSFULLY", 1)
                    self.print_success("Ubuntu 24.04 LTS security hardening setup complete!")
                    self.print_info("Run this script again anytime to update and verify")
                    return 0
                else:
                    return 1
            else:
                self.print_success("Download completed successfully")
                self.print_info("Run without --download-only to execute hardening")
                return 0
                
        except KeyboardInterrupt:
            self.print_warning("\nSetup interrupted by user")
            return 130
        except Exception as e:
            self.print_error(f"Unexpected error: {e}")
            self.logger.exception("Unexpected error occurred")
            return 1

def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="Ubuntu Security Hardening Setup - Python Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  sudo python3 setup.py                    # Full setup and hardening
  sudo python3 setup.py --download-only    # Download files only
  sudo python3 setup.py --local           # Use local files
  sudo python3 setup.py --version         # Show version

GitHub Repository: {__github__}
        """
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version=f'Ubuntu Security Hardening Setup v{__version__}'
    )
    
    parser.add_argument(
        '--download-only',
        action='store_true',
        help='Download hardening files only, do not execute'
    )
    
    parser.add_argument(
        '--local',
        action='store_true',
        help='Use local hardening files instead of downloading'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    return parser

def main() -> int:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger('ubuntu_hardening').setLevel(logging.DEBUG)
        
    setup = SecurityHardeningSetup()
    return setup.main(args)

if __name__ == "__main__":
    sys.exit(main()) 