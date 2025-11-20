
import os
import time
from utils.normalize import normalize
import re
from config.settings import settings

LOG_PATH = settings.ACCESS_LOG_PATH

PATTERNS = [

    # --- HTML TAGS / CLASSIC XSS ---
    r"</script",
    r"<img",
    r"<svg",
    r"<iframe",
    r"<object",
    r"<embed",
    r"<link",
    r"<style",
    r"srcdoc=",

    # --- EVENT HANDLERS ---
    r"on\w+\s*=",
    r"onerror",
    r"onload",
    r"onclick",
    r"onmouseover",
    r"onfocus",
    r"oninput",

    # --- JS SCHEMES ---
    r"javascript\s*:",
    r"data:text/html",
    r"vbscript:",

    # --- JS PAYLOADS ---
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"eval\s*\(",
    r"document\.cookie",
    r"document\.write",
    r"innerhtml",
    r"outerhtml",

    # --- DOM-BASED XSS ---
    r"document\.location",
    r"location\.hash",
    r"location\.search",
    r"window\.name",
    r"history\.pushState",
    r"new Function",

    # --- OBFUSCATION ---
    r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",   
    r"<\s*script",                                   
    r"<script.*?>",                             

    # --- ENCODING (URL, HTML ENTITIES, UNICODE) ---
    r"%3cscript",        
    r"%3c\s*svg",        
    r"&#x3c;script",       
    r"\\x3cscript", 
    r"%u003cscript",
    r"\\u003cscript",      
    r"u003cscript",       

    # --- POLYGLOT ---
    r"<svg\/onload",
    r"<svg\s*onload",
    
     #--- JSON XSS---
    r"\"\s*:\s*\"<script", 
    r"{.*<script.*}", 
]


def detect(line):
    text = normalize(line)
    matches = []
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            matches.append(p)
    if matches:
        return True, matches, "XSS injection"

    return False, None, None
