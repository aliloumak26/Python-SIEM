import time
import re
from datetime import datetime
from config.settings import settings

failed_logins = {}

MAX_ATTEMPTS = 5  
TIME_WINDOW = 10   


def detect(line):

    ip = extract_ip(line)
    method, url = parse_log_line(line)

    if not method or not url:
        return False, None, None


    if "/login" in url.lower():
        now = time.time()

        if ip not in failed_logins:
            failed_logins[ip] = []

        failed_logins[ip].append(now)

        failed_logins[ip] = [
            t for t in failed_logins[ip]
            if now - t < TIME_WINDOW
        ]

        if len(failed_logins[ip]) > MAX_ATTEMPTS:
            pattern = f"more_than_{MAX_ATTEMPTS}_requests_in_{TIME_WINDOW}s_from_{ip}"
            return True, pattern, "Brute Force"

    if "404" in line:
        return True, "404_error", "HTTP Error"

    if "500" in line:
        return True, "500_error", "HTTP Error"

    return False, None, None



def extract_ip(line):
    match = re.search(r"-\s*([0-9a-fA-F\:\.]+)\s*-\s*", line)
    if match:
        return match.group(1)
    return "unknown"



def parse_log_line(line):
    match = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b\s+([^\s]+)', line)
    if match:
        method, url = match.groups()
        return method, url
    return None, None
