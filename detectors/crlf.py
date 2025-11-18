#!/usr/bin/env python3
import os
import time
from utils.normalize import normalize
import re
from config.settings import settings


LOG_PATH = settings.ACCESS_LOG_PATH

# ----------------- CRLF INJECTION PATTERNS -----------------
PATTERNS = [
    r"%0d%0a",
    r"%0a%0d",
    r"%0d",
    r"%0a",
    r"%250d%250a",
    r"%250a%250d",
    r"\\r\\n",
    r"\\r",
    r"\\n",
    r"\r\n",
    r"\r",
    r"\n",
]

def detect(line):
    text = normalize(line)
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True, p, "CRLF Injection"

    return False, None, None
