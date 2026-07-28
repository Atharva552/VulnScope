import re


def get_severity(service: str):

    service = service.lower()

    high = [
        "http",
        "https",
        "ssl/http",
        "ftp",
        "smb",
        "mysql",
        "telnet",
        "rdp"
    ]

    medium = [
        "ssh",
        "smtp",
        "dns"
    ]

    if service in high:
        return "High"

    elif service in medium:
        return "Medium"

    return "Low"



def parse_nmap_output(output: str):

    findings = []

    pattern = r"(\d+)/tcp\s+open\s+([^\s]+)\s*(.*)"

    for line in output.splitlines():

        match = re.match(pattern, line)

        if match:

            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip()


            severity = get_severity(service)
            risk = "Unknown"
            recommendation = "No recommendation available."

            if service in ["http", "https"]:
                risk = "Web servers are common attack targets and may be vulnerable to XSS, SQL Injection, Directory Traversal or Remote Code Execution."
                recommendation = "Keep the web server updated, enable HTTPS, configure security headers, and regularly perform vulnerability assessments."

            elif service == "ssh":
                risk = "Weak passwords or outdated SSH versions may allow unauthorized access."
                recommendation = "Disable root login, use SSH keys, update OpenSSH regularly and restrict access."

            elif service == "ftp":
                risk = "FTP transmits data in plain text and is vulnerable to credential theft."
                recommendation = "Use SFTP/FTPS instead of FTP and disable anonymous login."

            elif service == "telnet":
                risk = "Telnet sends credentials without encryption."
                recommendation = "Disable Telnet and replace it with SSH."

            elif service == "mysql":
                risk = "Database exposure may lead to unauthorized data access."
                recommendation = "Restrict remote access, use strong passwords and update MySQL."

            elif service == "smtp":
                risk = "Mail servers can be abused for spam or information leakage."
                recommendation = "Disable open relay and keep the mail server updated."

            elif service == "dns":
                risk = "DNS servers may allow cache poisoning or amplification attacks."
                recommendation = "Disable recursion for public users and update DNS software."

            elif service == "smb":
                risk = "SMB services are frequently targeted by ransomware and remote exploits."
                recommendation = "Disable SMBv1, patch Windows regularly and restrict SMB access."

            findings.append({

                "port": port,

                "service": service,

                "version": version if version else "Unknown",

                "severity": severity,

                "risk": risk,

                "recommendation": recommendation

            })


    return findings



# ==================================
# SSL/TLS Parser
# ==================================

def parse_ssl_info(output: str):

    ssl_info = {

        "enabled": False,

        "issuer": "Unknown",

        "subject": "Unknown",

        "expires": "Unknown",

        "tls_version": "Unknown",

        "days_left": "Unknown"

    }


    if "ssl-cert" in output:

        ssl_info["enabled"] = True


    # Subject

    subject = re.search(
        r"Subject:\s*(.*)",
        output
    )

    if subject:

        ssl_info["subject"] = subject.group(1)



    # Expiry

    expiry = re.search(
        r"Not valid after:\s*(.*)",
        output
    )

    if expiry:

        ssl_info["expires"] = expiry.group(1)



    # TLS version

    tls = re.search(
        r"TLSv[\d.]+",
        output
    )

    if tls:

        ssl_info["tls_version"] = tls.group(0)


    return ssl_info



# ==================================
# HTTP Security Headers
# ==================================

def parse_headers(output: str):

    headers = []


    security_headers = [

        "Strict-Transport-Security",

        "Content-Security-Policy",

        "X-Frame-Options",

        "X-Content-Type-Options"

    ]


    for header in security_headers:


        if header in output:


            headers.append({

                "header": header,

                "status": "Present",

                "value": "Detected",

                "recommendation":
                "Keep this security header enabled."

            })


        else:


            headers.append({

                "header": header,

                "status": "Missing",

                "value": "-",

                "recommendation":
                "Configure this security header."

            })


    return headers