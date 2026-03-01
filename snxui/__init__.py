"""SNX VPN GUI Client"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("snxui")
except PackageNotFoundError:
    __version__ = "unknown"

__app_id__ = "com.snxui.SNXui"
