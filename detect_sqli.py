import os
from urllib.parse import unquote

LOG_PATH = os.environ.get("LOG_PATH", "C:\\Users\\Pc\\Documents\\Organigramme-Info\\Web-Dev-Backend\\access.log")

PATTERNS = [
    " or 1=1",
    "union select",
    "drop table",
    "; drop ",
    "sleep(",
    "benchmark(",
    "xp_cmdshell",
    "--",
    "/*",
]

def parse_line(line):
    #hadi on c jms tkon deja dict
    if isinstance(line, dict):
        return line
    # sinon
    parts = line.strip().split(" - ")
    if len(parts) < 5:
        return None
    
    ts = parts[0].strip()
    ip = parts[1].strip()
    req = parts[2].strip()      
    status = parts[3].strip()   
    duration = parts[4].strip() 
    tokens = req.split(" ", 1)
    method = tokens[0]
    path = tokens[1] if len(tokens) > 1 else ""

    return {
        "ts": ts,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "duration": duration,
        "raw": line.strip()
    }

def normalize(s: str) -> str : 
    if not s :
        return None
    
    '''unquote pour decoder URL-encoded characters kima %20 pour espace %27 pour apostrophe 
    ça speut matemchich so have to write exception handling'''
    try :
        return unquote(s).lower().strip()
    except :
        return s.lower().strip()
    
def alert(entry, reason):
    ts = entry.get("ts","Z")
    ip = entry.get("ip", "")
    method = entry.get("method", "")
    path = entry.get("path", "")
    msg = f"{ts} - ALERT SQLI - {ip} - {method} {path} - {reason}"
    print(msg)

def detect_sqli(entry) : 
    entry = parse_line(entry)
    if not entry :
        return None
    path = normalize(entry.get("path"))
    for pattern in PATTERNS :
        if pattern in path :
            alert(entry, f"pattern_string:{pattern}")
            return True
    
if __name__ == "__main__":
    example_line = "2025-10-12T21:31:05.580Z - 192.168.0.10 - GET /api/search?name='or 1=1-- - 200 - 2ms"
    entry = parse_line(example_line)
    print("Parsed:", entry)
    detected = detect_sqli(entry)
    print("Detected?", detected)