import os
import re
from urllib.parse import unquote

LOG_PATH = os.environ.get("LOG_PATH", r"C:\Users\Pc\Documents\Organigramme-Info\Web-Dev-Backend\access.log")

# ---------- MOTIFS CRLF ----------
CRLF_PATTERNS = [
    "%0d%0a", "%0a%0d",          
    "%250d%250a", "%250a%250d",   
    "%0d", "%0a",                 
    "\\r\\n", "\\r", "\\n",     
    "\r\n", "\r", "\n",          
]
LINE_RE = re.compile(
    r'^(?P<ts>[^-]+?)\s*-\s*(?P<ip>[^-]+?)\s*-\s*(?P<req>.+?)\s*-\s*(?P<status>\d{3})\s*-\s*(?P<duration>.+)$'
)


def parse_line(line):
    """
    Si on reçoit déjà un dict, on le renvoie direct 
    
    """
    if isinstance(line, dict):
        return line

    # enlève le newline final si y en a
    line = line.rstrip('\n')
    m = LINE_RE.match(line)
    if not m:
        # fallback simple : 
        parts = line.strip().split(" - ")
        if len(parts) >= 5:
            ts = parts[0].strip()
            ip = parts[1].strip()
            req = parts[2].strip()
            status = parts[3].strip()
            duration = " - ".join(parts[4:]).strip()
            tokens = req.split(" ", 1)
            method = tokens[0]
            path = tokens[1] if len(tokens) > 1 else ""
            return {
                "ts": ts, "ip": ip, "method": method, "path": path,
                "status": status, "duration": duration, "raw": line
            }
        # si ça colle pas, on renvoie None (ligne invalide)
        return None


    groups = m.groupdict()
    req = groups["req"].strip()
    tokens = req.split(" ", 1)
    method = tokens[0]
    path = tokens[1] if len(tokens) > 1 else ""
    return {
        "ts": groups["ts"].strip(),
        "ip": groups["ip"].strip(),
        "method": method,
        "path": path,
        "status": groups["status"].strip(),
        "duration": groups["duration"].strip(),
        "raw": line
    }
    
    
   # ---------- NORMALIZE ----------
   
def normalize(s):
    
    if not s:
        return ""
    try:
        s1 = unquote(s)   # premier décodage (%3C -> <)
        s2 = unquote(s1)  # deuxième (double-encodé)
        return s2.lower().strip()
    except Exception:
        try:
            return s.lower().strip()
        except Exception:
            return ""



# ---------- ALERT ----------
def alert(entry, reason):

    ts = entry.get("ts", "")
    ip = entry.get("ip", "")
    method = entry.get("method", "")
    path = entry.get("path", "")
    print(f"{ts} - ALERT CRLF - {ip} - {method} {path} - {reason}")

# ---------- DETECTION ----------


def detect_crlf(entry):
    """
    Retourne True si CRLF détecté, False si non, None si ligne invalide.
    """
    entry = parse_line(entry)
    if not entry:
        return None

    path = normalize(entry.get("path", ""))

    for p in CRLF_PATTERNS:
        if p in path:
            alert(entry, f"pattern:{p}")  
            return True


    return False

# ---------- PETIT SELF-TEST ----------

if __name__ == "__main__":
    # tests rapides pour vérifier que ça marche bien chez toi
    tests = [
        "2025-10-21T10:20:00.000Z - 203.0.113.30 - GET /vuln?x=%0d%0aSet-Cookie:evil=1 - 200 - 5ms",
        "2025-10-21T10:24:00.000Z - 203.0.113.34 - GET /mix?x=%250d%250aSet-Cookie:travail - 200 - 2ms",
        r"2025-10-21T10:23:00.000Z - 203.0.113.33 - GET /plain?x=\r\nSet-Cookie:bad=1 - 200 - 2ms",
    ]
    for t in tests:
        # debug minimal pour voir ce que le parser renvoie et si on detecte
        print("Parsed:", parse_line(t))
        print("Detected?", detect_crlf(t)) 
    

