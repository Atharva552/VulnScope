import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Missing HSTS header. Enable HTTP Strict Transport Security.",

    "Content-Security-Policy":
        "Missing CSP header. Helps prevent XSS attacks.",

    "X-Frame-Options":
        "Missing X-Frame-Options. Site may be vulnerable to Clickjacking.",

    "X-Content-Type-Options":
        "Missing X-Content-Type-Options. MIME sniffing protection disabled.",

    "Referrer-Policy":
        "Missing Referrer-Policy. Browser may leak sensitive URLs.",

    "Permissions-Policy":
        "Missing Permissions-Policy."
}


def check_security_headers(url: str):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = []

    try:

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True
        )

        headers = response.headers

        for header, recommendation in SECURITY_HEADERS.items():

            if header in headers:

                results.append({
                    "header": header,
                    "status": "Present",
                    "value": headers[header],
                    "recommendation": "OK"
                })

            else:

                results.append({
                    "header": header,
                    "status": "Missing",
                    "value": "-",
                    "recommendation": recommendation
                })

    except Exception as e:

        results.append({
            "header": "Connection",
            "status": "Error",
            "value": str(e),
            "recommendation": "Unable to retrieve headers."
        })

    return results