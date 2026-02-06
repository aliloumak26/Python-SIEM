
import re
from utils.normalize import normalize

PATTERNS = [
    r'\$gt\b', r'\$ne\b', r'\$where\b', r'\$regex\b', r'\$in\b', r'\$nin\b',
    r'\$or\b', r'\$and\b', r'\$exists\b', r'\$elemMatch\b'
]

def detect(line):
    text = normalize(line)
    matches = []
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            matches.append(p)
    if matches:
        return True, matches, "NoSQL Injection"

    return False, None, None
