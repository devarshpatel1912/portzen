"""Process Detector Module
Safely retrieves process name, path, command line, and user context given a process ID.
"""

import psutil
from config import logger

def get_process_info(pid: int | None) -> dict:
    """Retrieve process details with robust error handling for restricted permissions."""
    if pid is None or pid < 0:
        return {
            "pid": None,
            "process_name": "Unknown",
            "exe": None,
            "cmdline": "",
            "username": None,
            "status": "No PID available",
            "accessible": False,
        }

    try:
        proc = psutil.Process(pid)
        try:
            name = proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            name = f"Process [{pid}]"

        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = None

        try:
            cmdline = " ".join(proc.cmdline())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            cmdline = ""

        try:
            username = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            username = None

        return {
            "pid": pid,
            "process_name": name,
            "exe": exe,
            "cmdline": cmdline,
            "username": username,
            "status": "Active",
            "accessible": True,
        }
    except psutil.NoSuchProcess:
        return {
            "pid": pid,
            "process_name": f"Terminated [{pid}]",
            "exe": None,
            "cmdline": "",
            "username": None,
            "status": "Process terminated during inspection",
            "accessible": False,
        }
    except psutil.AccessDenied:
        return {
            "pid": pid,
            "process_name": "Access Denied",
            "exe": None,
            "cmdline": "",
            "username": None,
            "status": "Elevated permissions required",
            "accessible": False,
        }
    except Exception as e:
        logger.warning(f"Unexpected error inspecting PID {pid}: {e}")
        return {
            "pid": pid,
            "process_name": f"PID {pid}",
            "exe": None,
            "cmdline": "",
            "username": None,
            "status": "Inspection error",
            "accessible": False,
        }
