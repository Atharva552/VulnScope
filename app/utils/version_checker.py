import re


def check_version(service: str, version: str):

    service = service.lower()
    version = version.lower()

    # Default values
    risk = ""
    recommendation = ""

    # Apache
    if service == "http" and "apache" in version:

        match = re.search(r"apache.*?(\d+\.\d+\.\d+)", version)

        if match:
            ver = tuple(map(int, match.group(1).split(".")))

            if ver < (2, 4, 50):
                risk = "Outdated Apache version detected."
                recommendation = "Upgrade Apache to the latest stable release."

    # OpenSSH
    elif service == "ssh":

        match = re.search(r"openssh\s+(\d+\.\d+)", version)

        if match:

            ver = float(match.group(1))

            if ver < 8.0:
                risk = "Outdated OpenSSH version."
                recommendation = "Upgrade OpenSSH to a supported version."

    # VSFTPD
    elif service == "ftp":

        if "vsftpd 2.3.4" in version:
            risk = "Known vulnerable VSFTPD version."
            recommendation = "Upgrade VSFTPD immediately."

    return risk, recommendation