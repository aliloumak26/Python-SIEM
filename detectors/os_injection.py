import re
from utils.normalize import normalize

def detect(line):
    patterns = [
        r";",
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
    
    for p in patterns:
        text = normalize()
        if re.search(p, text, re.IGNORECASE):
            return True, p, "OS_command_Injection_detected"
    
    return False, None, None