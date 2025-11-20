import os
import time
import re
from utils.normalize import normalize
from config.settings import settings

LOG_PATH = settings.ACCESS_LOG_PATH

PATTERNS = [
    r"&&",
    r"&",
    r"\|\|",
    r"\|",
    r"\$\(",
    r"`",
    r"%3b",
    r"%26",
    r"%7c",
    r"%24%28",
    r"\$path",
    r"\$home",
    r"\$user",
    r"\$shell",
    r"\brm\b",
    r"\bls\b",
    r"bwhoami\b",
    r"\bcat\b",
    r"\bhmod\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bping\b",
    r"\bshutdown\b",
]

    
def detect(line):
    text = normalize(line)
    matches = []
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            matches.append(p)
    if matches:
        return True, matches, "OS Command Injection"

    return False, None, None