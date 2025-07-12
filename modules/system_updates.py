"""
System Updates Module

Handles system package updates with intelligent caching and idempotency.
Ensures updates are performed efficiently without unnecessary operations.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
"""

import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


class SystemUpdater:
    """Manages system package updates with idempotency."""
    
    def __init__(self, state_manager, logger: logging.Logger):
        """Initialize the system updater."""
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
            
    def _is_update_needed(self) -> bool:
        """Check if system updates are needed."""
        # Check if updates were performed today
        state = self.state_manager.get_state()
        last_update = state.get("system_updates", {}).get("last_update")
        
        if last_update:
            try:
                last_update_date = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                hours_since_update = (now - last_update_date).total_seconds() / 3600
                
                if hours_since_update < 24:
                    self.logger.info(f"Updates performed {hours_since_update:.1f} hours ago, skipping")
                    return False
            except Exception as e:
                self.logger.warning(f"Could not parse last update time: {e}")
                
        return True
        
    def update_package_lists(self) -> bool:
        """Update package lists."""
        self.logger.info("Updating package lists...")
        
        success, output = self._run_command(["apt-get", "update", "-y"])
        if success:
            self.logger.info("Package lists updated successfully")
            return True
        else:
            self.logger.error("Failed to update package lists")
            return False
            
    def check_available_upgrades(self) -> int:
        """Check how many packages can be upgraded."""
        success, output = self._run_command(["apt", "list", "--upgradable"], check=False)
        if success:
            # Count lines minus header
            lines = output.strip().split('\n')
            upgrade_count = max(0, len(lines) - 1)
            self.logger.info(f"Found {upgrade_count} packages available for upgrade")
            return upgrade_count
        else:
            self.logger.warning("Could not check available upgrades")
            return 0
            
    def upgrade_packages(self) -> bool:
        """Upgrade installed packages."""
        upgrade_count = self.check_available_upgrades()
        
        if upgrade_count == 0:
            self.logger.info("All packages are already up to date")
            return True
            
        self.logger.info(f"Upgrading {upgrade_count} packages...")
        
        success, output = self._run_command([
            "apt-get", "upgrade", "-y",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold"
        ])
        
        if success:
            self.logger.info("Packages upgraded successfully")
            
            # Record upgrade in state
            self.state_manager.update_state({
                "system_updates": {
                    "last_update": datetime.now(timezone.utc).isoformat(),
                    "packages_upgraded": upgrade_count,
                    "status": "completed"
                }
            })
            return True
        else:
            self.logger.error("Package upgrade failed")
            return False
            
    def dist_upgrade(self) -> bool:
        """Perform distribution upgrade."""
        self.logger.info("Performing distribution upgrade...")
        
        success, output = self._run_command([
            "apt-get", "dist-upgrade", "-y",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold"
        ])
        
        if success:
            self.logger.info("Distribution upgrade completed successfully")
            return True
        else:
            self.logger.warning("Distribution upgrade had issues (non-critical)")
            return True  # Don't fail the entire process for dist-upgrade issues
            
    def cleanup_packages(self) -> bool:
        """Clean up unnecessary packages and cache."""
        self.logger.info("Cleaning up packages...")
        
        # Remove unnecessary packages
        success1, _ = self._run_command(["apt-get", "autoremove", "-y"])
        
        # Clean package cache
        success2, _ = self._run_command(["apt-get", "autoclean"])
        
        if success1 and success2:
            self.logger.info("Package cleanup completed successfully")
            return True
        else:
            self.logger.warning("Package cleanup had some issues")
            return True  # Don't fail for cleanup issues
            
    def check_ubuntu_pro(self) -> Dict[str, str]:
        """Check Ubuntu Pro status."""
        try:
            success, output = self._run_command(["pro", "status", "--format=json"], check=False)
            if success:
                import json
                pro_data = json.loads(output)
                attached = pro_data.get("attached", False)
                
                self.logger.info(f"Ubuntu Pro status: {'Active' if attached else 'Not active'}")
                return {
                    "status": "active" if attached else "inactive",
                    "details": output
                }
            else:
                self.logger.info("Ubuntu Pro not available or not configured")
                return {"status": "unavailable"}
        except Exception as e:
            self.logger.warning(f"Could not check Ubuntu Pro status: {e}")
            return {"status": "unknown"}
            
    def update_system(self, verify_only: bool = False) -> bool:
        """
        Main system update function with idempotency.
        
        Args:
            verify_only: If True, only verify current state without making changes
            
        Returns:
            bool: True if updates completed successfully or are not needed
        """
        if verify_only:
            # For verification, just check if updates were performed recently
            return self.state_manager.is_recent_completion("system-updates", hours=24)
            
        # Check if updates are needed
        if not self._is_update_needed():
            self.logger.info("System updates not needed (performed recently)")
            return True
            
        try:
            # Check Ubuntu Pro status
            pro_status = self.check_ubuntu_pro()
            
            # Update package lists
            if not self.update_package_lists():
                return False
                
            # Upgrade packages
            if not self.upgrade_packages():
                return False
                
            # Perform distribution upgrade
            if not self.dist_upgrade():
                return False
                
            # Clean up packages
            if not self.cleanup_packages():
                return False
                
            self.logger.info("System updates completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"System update failed: {e}")
            return False 