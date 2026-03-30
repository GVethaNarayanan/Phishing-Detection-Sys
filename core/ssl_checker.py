import ssl
import socket


class SSLChecker:

    def check_ssl_certificate(self, domain):

        try:
            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:

                    cert = ssock.getpeercert()

                    return {
                        "valid": True,
                        "issuer": cert.get("issuer"),
                        "subject": cert.get("subject")
                    }

        except Exception as e:

            # Fail-safe: Unknown ≠ Invalid
            return {
                "valid": None,
                "error": str(e)
            }
