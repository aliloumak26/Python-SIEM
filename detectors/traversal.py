
import re
from utils.normalize import normalize

PATTERNS = [
    r'\.\./', r'\.\.\\', r'/etc/passwd', r'/etc/shadow', r'/etc/group',
    r'\bwin\.ini\b', r'\bweb\.config\b', r'\.htaccess\b', r'\.env\b',
    r'\bconfig\.php\b', r'\bsettings\.py\b', r'\bbackup.*\.zip\b'
]

def detect(line):
    text = normalize(line)
    matches = []
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            matches.append(p)
    if matches:
        return True, matches, "Path Traversal"

    return False, None, None
