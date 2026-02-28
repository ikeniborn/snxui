"""System integration: autostart, D-Bus tray, polkit privilege escalation."""

from .tray_manager import TrayManager
from .privilege_handler import PrivilegeHandler
from .autostart import AutostartManager

__all__ = ["TrayManager", "PrivilegeHandler", "AutostartManager"]
