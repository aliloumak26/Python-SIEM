import re
from utils.normalize import normalize_log

def detect(log_line):
 
    line = normalize_log(log_line)

    sensitive_methods = ["post", "put", "delete"]

    method_match = re.search(r'"(post|put|delete)\s+([^\s]+)', line)
    if method_match:
        method = method_match.group(1)
        endpoint = method_match.group(2)


        if "csrf_token=missing" in line or "csrf=absent" in line:
            return {
                "attack_type": "CSRF Attack",
                "method": method.upper(),
                "endpoint": endpoint,
                "description": "Sensitive action without CSRF token",
                "log": log_line
            }

    
        if 'referer="-"' in line or "referer=absent" in line:
            return {
                "attack_type": "CSRF (Missing Referer)",
                "method": method.upper(),
                "endpoint": endpoint,
                "description": "Sensitive request without Referer header",
                "log": log_line
            }

    
        referer_match = re.search(r'referer="([^"]+)"', line)
        if referer_match:
            referer = referer_match.group(1)
            if "localhost" not in referer:
                return {
                    "attack_type": "Cross-Site Request Forgery",
                    "method": method.upper(),
                    "endpoint": endpoint,
                    "description": f"Request coming from external site: {referer}",
                    "log": log_line
                }

    return None
