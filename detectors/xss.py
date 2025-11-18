#!/usr/bin/env python3
import os
import time
from utils.normalize import normalize
import re
from config.settings import settings


LOG_PATH = settings.ACCESS_LOG_PATH

# ----------------- XSS PATTERNS -----------------
PATTERNS = [
    # HTML/JS tags
    r"<script",
    r"</script",
    r"<img",
    r"<svg",
    r"<iframe",
    r"<body",
    r"<meta",
    r"srcdoc=",

    # JS schemes
    r"javascript:",
    r"data:text/html",
    
    # Event handlers
    r"onerror=",
    r"onload=",
    r"onclick=",
    r"onmouseover=",
    r"onfocus=",
    r"oninput=",

    # JS functions
    r"alert\(",
    r"prompt\(",
    r"confirm\(",
    r"document\.cookie",
    r"document\.write",
    r"innerhtml",
    r"eval\(",
]

def detect(line):
    text = normalize(line)
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True, p, "XSS"

    return False, None, None
