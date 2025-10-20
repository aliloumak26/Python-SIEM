import os
from urllib.parse import unquote_plus

LOG_PATH = os.environ.get("LOG_PATH", r"C:\Users\Pc\Documents\Organigramme-Info\Web-Dev-Backend\access.log")
# ---------- PATTERNS XSS ----------
# motifs simples qu'on va chercher dans la requête décodée
PATTERNS = [
    "<script",          
    "javascript:",      
    "onerror=",        
    "onload=",          
    "onclick=",         
    "onmouseover=",
    "alert(",           
    "document.cookie", 
    "document.write",
    "innerhtml",       
    "eval(",          
    "<img",            
    "<svg",             
    "<iframe",      
    "srcdoc=",          
    "<body",            
    "<meta",            
    "</script>",        
]
# ---------- PARSING ----------

def parse_line(line):
    # si c'est déjà un dict retourné 
    if isinstance(line, dict):
        return line
    #else
    parts = line.strip().split(" - ")
    if len(parts) < 5:
     # si c'est pas le bon format, on skip
        return None
    
    ts = parts[0].strip()
    ip = parts[1].strip()
    req = parts[2].strip()
    status = parts[3].strip()
    duration = parts[4].strip()
    tokens = req.split(" ", 1)
    method = tokens[0]
    path = tokens[1] if len(tokens) > 1 else ""

    # on renvoie un dict standard pour travailler proprement
    return {
        "ts": ts,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "duration": duration,
        "raw": line.strip()
    }
   # ---------- NORMALISATION ----------
    
def normalize(s: str) -> str:
    """Décodage URL + lowercase + strip. Retourne '' si rien."""
    if not s:
        return ""
    try:
        return unquote(s).lower().strip()
    except Exception:
        try:
            return s.lower().strip()
        except Exception:
            return ""
        
# ---------- ALERTE ---------- 
     
def alert(entry, reason):
    ts = entry.get("ts", "Z")
    ip = entry.get("ip", "")
    method = entry.get("method", "")
    path = entry.get("path", "")
    msg = f"{ts} - ALERT XSS - {ip} - {method} {path} - {reason}"
    print(msg)  
    
 # ---------- DETECTION XSS ----------
    
def detect_xss(entry):
    """
     Retourne True si on détecte un pattern XSS, False sinon, None si ligne invalide.
    """
    entry = parse_line(entry)
    if not entry:
        return None


    path = normalize(entry.get("path"))

    # check rapide pour chercher les patterns
    for p in PATTERNS:
        if p in path:
            alert(entry, f"pattern_string:{p}")
            return True

    
    try:

        if "?" in path:
            _, qs = path.split("?", 1)
        
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    nv = normalize(v)
                    for p in PATTERNS:
                        if p in nv:
                            alert(entry, f"pattern_param:{p} (param:{k})")
                            return True
                else:
            
                    nv = normalize(pair)
                    for p in PATTERNS:
                        if p in nv:
                            alert(entry, f"pattern_param:{p} (bare param)")
                            return True
    except Exception:
        pass

    return False   
# ---------- TEST RAPIDE ----------
if __name__ == "__main__":
    # exemple vulnérable / détection XSS
    example_line = "2025-10-20T19:00:00.000Z - 203.0.113.5 - GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E - 200 - 5ms"
    entry = parse_line(example_line)
    print("Parsed:", entry)
    detected = detect_xss(entry)
    print("Detected?", detected)    
