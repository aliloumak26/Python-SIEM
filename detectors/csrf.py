from utils.normalize import normalize
import re

def detect(log_line):
    line = normalize(log_line)
    sensitive_methods = ["post", "put", "delete"]
    matches = []

    method_match = re.search(r'"(post|put|delete)\s+([^\s]+)', line)
    if method_match:
        method = method_match.group(1)
        endpoint = method_match.group(2)

        if "csrf_token=missing" in line or "csrf=absent" in line:
            matches.append(f"missing_token:{method}:{endpoint}")
            return True, matches, "CSRF Attack"

        if 'referer="-"' in line or "referer=absent" in line:
            matches.append(f"missing_referer:{method}:{endpoint}")
            return True, matches, "CSRF (Missing Referer)"

        referer_match = re.search(r'referer="([^"]+)"', line)
        if referer_match:
            referer = referer_match.group(1)
            if "localhost" not in referer:
                matches.append(f"external_referer:{referer}")
                return True, matches, "Cross-Site Request Forgery"

    return False, None, None
