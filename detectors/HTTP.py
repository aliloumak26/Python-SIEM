from utils.normalize import normalize
import re

class HTTPDetector:
    def __init__(self):
        self.suspicious_methods = {"PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT"}

        self.scanner_signatures = [
            "sqlmap",
            "nikto",
            "nmap",
            "dirbuster",
            "gobuster",
            "wpscan",
            "curl",
            "python-requests",
            "httpclient",
        ]

        self.sensitive_paths = [
            "/admin",
            "/login",
            "/wp-admin",
            "/phpmyadmin",
            "/.env",
            "/config",
            "/backup",
            "/shell",
        ]

    def detect(self, log_line):
        text = normalize(log_line)
        matches = []
        
        # Check for suspicious methods
        for method in self.suspicious_methods:
            if re.search(rf"\b{method}\b", text, re.IGNORECASE):
                matches.append(f"suspicious_method:{method}")
        
        # Check for scanner signatures
        for sig in self.scanner_signatures:
            if re.search(re.escape(sig), text, re.IGNORECASE):
                matches.append(f"scanner_signature:{sig}")
        
        # Check for sensitive paths
        for path in self.sensitive_paths:
            if re.search(re.escape(path), text, re.IGNORECASE):
                matches.append(f"sensitive_path:{path}")

        if matches:
            return True, matches, "HTTP Scanner"
        
        return False, None, None

# Singleton instance for the SIEM engine
_detector = HTTPDetector()

def detect(log_line):
    return _detector.detect(log_line)
