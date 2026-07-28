from urllib.parse import urlparse


def clean_target(target: str):
    """
    Returns:
        host -> example.com
        port -> 80/443/8000 or None
    """

    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port
    else:
        if ":" in target:
            host, port = target.split(":", 1)
            try:
                port = int(port)
            except ValueError:
                port = None
        else:
            host = target
            port = None

    return host, port