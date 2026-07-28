import subprocess
import os

# Windows Nmap Path
NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def run_nmap(target, port=None, profile="service"):
    """
    Run Nmap scan.

    target : example.com / 127.0.0.1
    port   : 80 / 443 / 8000 / None
    """

    if not os.path.exists(NMAP_PATH):
        return f"ERROR: Nmap not found at:\n{NMAP_PATH}"

    command = [NMAP_PATH]

    # -------------------------
    # Scan Profile
    # -------------------------

    if profile == "quick":
        pass

    elif profile == "service":
        command.append("-sV")

    elif profile == "aggressive":
        command.extend([
            "-Pn",
            "-A",
            "--version-all"
        ])

    elif profile == "full":
        command.extend([
            "-p-",
            "-sV"
        ])

    else:
        command.append("-sV")

    # -------------------------
    # Custom Port
    # -------------------------

    if port is not None and profile != "full":
        command.extend([
            "-p",
            str(port)
        ])

    # -------------------------
    # Target
    # -------------------------

    command.append(target)

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            return result.stderr

        return result.stdout

    except subprocess.TimeoutExpired:
        return "ERROR: Scan timed out."

    except Exception as e:
        return f"ERROR: {str(e)}"