"""
State Manager Module

Handles all state tracking and idempotency management for the Ubuntu Security
Hardening system. Provides robust persistence and recovery capabilities.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class StateManager:
    """Manages persistent state for idempotent hardening operations."""
    
    def __init__(self):
        """Initialize the state manager."""
        self.state_dir = Path("/var/lib/security-hardening")
        self.state_file = self.state_dir / "hardening-state.json"
        self.backup_dir = Path("/var/backups/security-hardening")
        self.log_dir = Path("/var/log/security-hardening")
        
        # Ensure directories exist
        for directory in [self.state_dir, self.backup_dir, self.log_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
            
        self._initialize_state()
        
    def _initialize_state(self) -> None:
        """Initialize state file if it doesn't exist."""
        if not self.state_file.exists():
            initial_state = {
                "version": "5.0",
                "created": datetime.now(timezone.utc).isoformat(),
                "hardening_runs": 0,
                "last_run": None,
                "hardening_completed": False,
                "completed_phases": [],
                "phase_timestamps": {},
                "system_info": {},
                "package_states": {},
                "firewall_rules": [],
                "crowdsec_collections": [],
                "backup_files": [],
                "emergency_states": []
            }
            self._save_state(initial_state)
            
    def _save_state(self, state: Dict[str, Any]) -> None:
        """Save state to file with proper permissions."""
        try:
            # Create backup of existing state
            if self.state_file.exists():
                backup_file = self.state_dir / f"state-backup-{int(datetime.now().timestamp())}.json"
                self.state_file.rename(backup_file)
                
            # Write new state
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
                
            self.state_file.chmod(0o600)
            
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
            raise
            
    def get_state(self) -> Dict[str, Any]:
        """Get current state."""
        try:
            with open(self.state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load state, using defaults: {e}")
            self._initialize_state()
            return self.get_state()
            
    def update_state(self, updates: Dict[str, Any]) -> None:
        """Update state with new values."""
        state = self.get_state()
        state.update(updates)
        state["last_modified"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)
        
    def initialize_new_run(self) -> None:
        """Initialize a new hardening run."""
        state = self.get_state()
        state["hardening_runs"] += 1
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        state["current_run_id"] = f"run-{state['hardening_runs']}-{int(datetime.now().timestamp())}"
        self._save_state(state)
        
    def is_phase_completed(self, phase_name: str) -> bool:
        """Check if a hardening phase has been completed."""
        state = self.get_state()
        return phase_name in state.get("completed_phases", [])
        
    def mark_phase_completed(self, phase_name: str) -> None:
        """Mark a hardening phase as completed."""
        state = self.get_state()
        
        if phase_name not in state.get("completed_phases", []):
            state.setdefault("completed_phases", []).append(phase_name)
            
        state.setdefault("phase_timestamps", {})[phase_name] = datetime.now(timezone.utc).isoformat()
        
        self._save_state(state)
        
        # Create individual phase marker for reliability
        phase_marker = self.state_dir / f"phase-{phase_name}-completed"
        phase_marker.write_text(datetime.now(timezone.utc).isoformat())
        phase_marker.chmod(0o600)
        
    def get_phase_timestamp(self, phase_name: str) -> Optional[str]:
        """Get the timestamp when a phase was completed."""
        state = self.get_state()
        return state.get("phase_timestamps", {}).get(phase_name)
        
    def mark_hardening_completed(self) -> None:
        """Mark the entire hardening process as completed."""
        state = self.get_state()
        state["hardening_completed"] = True
        state["completion_timestamp"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)
        
        # Create completion marker
        completion_marker = self.state_dir / "hardening-completed"
        completion_marker.write_text(datetime.now(timezone.utc).isoformat())
        completion_marker.chmod(0o600)
        
    def save_emergency_state(self, error_type: str, error_message: str) -> None:
        """Save emergency state information for recovery."""
        state = self.get_state()
        
        emergency_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_type": error_type,
            "error_message": error_message,
            "current_phase": getattr(self, '_current_phase', 'unknown'),
            "run_id": state.get("current_run_id", "unknown")
        }
        
        state.setdefault("emergency_states", []).append(emergency_info)
        self._save_state(state)
        
        # Create emergency marker
        emergency_marker = self.state_dir / f"emergency-{int(datetime.now().timestamp())}"
        emergency_marker.write_text(json.dumps(emergency_info, indent=2))
        emergency_marker.chmod(0o600)
        
    def record_package_state(self, package_name: str, state_info: Dict[str, Any]) -> None:
        """Record package installation state."""
        state = self.get_state()
        state.setdefault("package_states", {})[package_name] = {
            **state_info,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self._save_state(state)
        
    def get_package_state(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get package installation state."""
        state = self.get_state()
        return state.get("package_states", {}).get(package_name)
        
    def record_firewall_rule(self, rule_info: Dict[str, Any]) -> None:
        """Record firewall rule configuration."""
        state = self.get_state()
        rule_info["timestamp"] = datetime.now(timezone.utc).isoformat()
        state.setdefault("firewall_rules", []).append(rule_info)
        self._save_state(state)
        
    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Get recorded firewall rules."""
        state = self.get_state()
        return state.get("firewall_rules", [])
        
    def record_crowdsec_collection(self, collection_name: str, status: str) -> None:
        """Record CrowdSec collection installation."""
        state = self.get_state()
        collection_info = {
            "name": collection_name,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        state.setdefault("crowdsec_collections", []).append(collection_info)
        self._save_state(state)
        
    def get_crowdsec_collections(self) -> List[Dict[str, Any]]:
        """Get recorded CrowdSec collections."""
        state = self.get_state()
        return state.get("crowdsec_collections", [])
        
    def record_backup_file(self, original_path: str, backup_path: str) -> None:
        """Record a backup file creation."""
        state = self.get_state()
        backup_info = {
            "original_path": original_path,
            "backup_path": backup_path,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        state.setdefault("backup_files", []).append(backup_info)
        self._save_state(state)
        
    def get_backup_files(self) -> List[Dict[str, Any]]:
        """Get list of backup files."""
        state = self.get_state()
        return state.get("backup_files", [])
        
    def create_backup_file(self, file_path: str) -> str:
        """Create a backup of a configuration file."""
        original_path = Path(file_path)
        
        if not original_path.exists():
            raise FileNotFoundError(f"File to backup does not exist: {file_path}")
            
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_filename = f"{original_path.name}.backup-{timestamp}"
        backup_path = self.backup_dir / backup_filename
        
        # Copy file to backup location
        import shutil
        shutil.copy2(original_path, backup_path)
        backup_path.chmod(0o600)
        
        # Record backup
        self.record_backup_file(str(original_path), str(backup_path))
        
        logging.info(f"Created backup: {file_path} -> {backup_path}")
        return str(backup_path)
        
    def is_recent_completion(self, phase_name: str, hours: int = 24) -> bool:
        """Check if a phase was completed recently."""
        timestamp_str = self.get_phase_timestamp(phase_name)
        if not timestamp_str:
            return False
            
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            return (now - timestamp).total_seconds() < (hours * 3600)
        except Exception:
            return False
            
    def generate_hardening_report(self) -> str:
        """Generate a comprehensive hardening report."""
        state = self.get_state()
        
        report_path = self.log_dir / f"hardening-report-{int(datetime.now().timestamp())}.txt"
        
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("Ubuntu Security Hardening Report\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"Script Version: {state.get('version', 'unknown')}\n")
            f.write(f"Total Runs: {state.get('hardening_runs', 0)}\n")
            f.write(f"Last Run: {state.get('last_run', 'never')}\n")
            f.write(f"Hardening Completed: {'Yes' if state.get('hardening_completed') else 'No'}\n\n")
            
            # Completed phases
            f.write("Completed Phases:\n")
            f.write("-" * 20 + "\n")
            for phase in state.get("completed_phases", []):
                timestamp = state.get("phase_timestamps", {}).get(phase, "unknown")
                f.write(f"✓ {phase} ({timestamp})\n")
            f.write("\n")
            
            # Package states
            if state.get("package_states"):
                f.write("Package Installation States:\n")
                f.write("-" * 30 + "\n")
                for pkg, info in state.get("package_states", {}).items():
                    f.write(f"• {pkg}: {info.get('status', 'unknown')}\n")
                f.write("\n")
                
            # Firewall rules
            if state.get("firewall_rules"):
                f.write("Firewall Rules:\n")
                f.write("-" * 15 + "\n")
                for rule in state.get("firewall_rules", []):
                    f.write(f"• {rule.get('description', 'Rule')}: {rule.get('status', 'unknown')}\n")
                f.write("\n")
                
            # CrowdSec collections
            if state.get("crowdsec_collections"):
                f.write("CrowdSec Collections:\n")
                f.write("-" * 20 + "\n")
                for collection in state.get("crowdsec_collections", []):
                    f.write(f"• {collection.get('name', 'Unknown')}: {collection.get('status', 'unknown')}\n")
                f.write("\n")
                
            # Backup files
            if state.get("backup_files"):
                f.write("Configuration Backups:\n")
                f.write("-" * 25 + "\n")
                for backup in state.get("backup_files", []):
                    f.write(f"• {backup.get('original_path', 'Unknown')} -> {backup.get('backup_path', 'Unknown')}\n")
                f.write("\n")
                
            # Emergency states
            if state.get("emergency_states"):
                f.write("Emergency States (Issues):\n")
                f.write("-" * 30 + "\n")
                for emergency in state.get("emergency_states", []):
                    f.write(f"• {emergency.get('timestamp', 'Unknown')}: {emergency.get('error_type', 'Unknown')} - {emergency.get('error_message', 'No details')}\n")
                f.write("\n")
                
        report_path.chmod(0o600)
        return str(report_path)
        
    def cleanup_old_states(self, days: int = 30) -> None:
        """Clean up old state files and backups."""
        import time
        
        cutoff_time = time.time() - (days * 24 * 3600)
        
        # Clean up old backup states
        for backup_file in self.state_dir.glob("state-backup-*.json"):
            try:
                if backup_file.stat().st_mtime < cutoff_time:
                    backup_file.unlink()
                    logging.info(f"Cleaned up old state backup: {backup_file}")
            except Exception as e:
                logging.warning(f"Failed to clean up {backup_file}: {e}")
                
        # Clean up old emergency markers
        for emergency_file in self.state_dir.glob("emergency-*"):
            try:
                if emergency_file.stat().st_mtime < cutoff_time:
                    emergency_file.unlink()
                    logging.info(f"Cleaned up old emergency marker: {emergency_file}")
            except Exception as e:
                logging.warning(f"Failed to clean up {emergency_file}: {e}")
                
        logging.info(f"State cleanup completed for files older than {days} days") 