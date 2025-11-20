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
    r"set-cookie:.*\r\n",
    r"location:.*\r\n",
    r"content-length:.*\r\n",
    r"\u000d",
    r"\u000a",
    r"%0d%0d%0a",
    r"%0a%0a%0d",
    r"[\r\n]+.*:",

<<<<<<< HEAD
=======



>>>>>>> 00a3af7d333a9ece957859fe69ef4ce0062163af
]

def detect(line):
    text = normalize(line)
    matches = []
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            matches.append(p)
    if matches:
        return True, matches, "CRLF Injection"

    return False, None, None