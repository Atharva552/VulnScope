import ssl
import socket
from datetime import datetime


def get_ssl_info(host, port=443):
    """
    Retrieve SSL/TLS certificate information.

    Returns:
        enabled
        issuer
        subject
        expires
        days_left
        tls_version
        cipher
    """

    ssl_info = {
        "enabled": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "expires": "Unknown",
        "days_left": "Unknown",
        "tls_version": "Unknown",
        "cipher": "Unknown"
    }

    try:

        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (host, port),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as ssock:

                cert = ssock.getpeercert()

                ssl_info["enabled"] = True

                ssl_info["tls_version"] = ssock.version()

                cipher = ssock.cipher()

                if cipher:
                    ssl_info["cipher"] = cipher[0]

                # ------------------------
                # Issuer
                # ------------------------

                issuer = {}

                for item in cert.get("issuer", []):
                    issuer.update(dict(item))

                ssl_info["issuer"] = issuer.get(
                    "organizationName",
                    issuer.get("commonName", "Unknown")
                )

                # ------------------------
                # Subject
                # ------------------------

                subject = {}

                for item in cert.get("subject", []):
                    subject.update(dict(item))

                ssl_info["subject"] = subject.get(
                    "commonName",
                    "Unknown"
                )

                # ------------------------
                # Expiry
                # ------------------------

                expire = cert.get("notAfter")

                if expire:

                    expiry = datetime.strptime(
                        expire,
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    ssl_info["expires"] = expiry.strftime("%d-%m-%Y")

                    ssl_info["days_left"] = (
                        expiry - datetime.utcnow()
                    ).days

    except socket.timeout:

        ssl_info["error"] = "Connection timed out."

    except ConnectionRefusedError:

        ssl_info["error"] = "Connection refused."

    except ssl.SSLError as e:

        ssl_info["error"] = f"SSL Error: {e}"

    except socket.gaierror:

        ssl_info["error"] = "Hostname could not be resolved."

    except Exception as e:

        ssl_info["error"] = str(e)

    return ssl_info