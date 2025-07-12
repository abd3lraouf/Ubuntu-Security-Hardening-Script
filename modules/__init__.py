"""
Ubuntu Security Hardening - Modules Package

This package contains all the modular components for Ubuntu security hardening.
Each module is responsible for a specific aspect of system security.

Author: Abdelraouf Sabri
GitHub: https://github.com/abd3lraouf/Ubuntu-Security-Hardening-Script
License: MIT
Version: 5.0
"""

__version__ = "5.0"
__author__ = "Abdelraouf Sabri"

# Module exports
__all__ = [
    'StateManager',
    'SystemUpdater', 
    'PackageManager',
    'FirewallManager',
    'CrowdSecManager',
    'SystemVerifier'
] 