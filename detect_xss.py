
import os
import time
from urllib.parse import unquote
import re

LOG_PATH = os.environ.get(
    "LOG_PATH",
    r"C:\Users\HP\Web-Dev-Backend\access.log"   # Chemin vers ton access.log
)

PATTERNS = [
    # BALISES HTML LIEES AU XSS
    r"<script",      
    r"</script",      
    r"<img",          
    r"<svg",         
    r"<iframe",        
    r"<body",          
    r"<meta",          
    r"srcdoc=",    
       
    #  SCHEMAS JAVASCRIPT DANGEREUX
    r"javascript:",    
    r"data:text/html",

    #EVENEMENTS HTML (ACTIONS ONXXXX=)
    r"on\w+=",     

    # FONCTIONS JS UTILISÉES DANS LES ATTQUES XSS
    r"alert\(",        
    r"prompt\(",     
    r"confirm\(",      
    r"document\.cookie", 
    r"document\.write", 
    r"innerhtml",       
    r"eval\(",           

    # DETECTION AVANCÉE : QUOTES ET BALISES BRISEES
    r"['\"]\s*>",      
    r"><",              
    r"</\w+>",         
]

def normalize(s: str) -> str:
    """
    Nettoie une ligne du log pour détecter l'attaque :
    - Double décodage URL (comme XSStrike)
    - Conversion HTML entities
    - Supprime backslashes
    - Minuscule
    """
    if not s:
        return ""

    try:
        decoded = unquote(s)
        decoded = unquote(decoded)
        decoded = decoded.replace("&lt;", "<").replace("&gt;", ">")
        decoded = decoded.replace('\\"', '"').replace("\\'", "'").replace("\\", "")

        return decoded.lower().strip()
    except:
        return str(s).lower().strip()

def check_line(line):
    normalized = normalize(line)

    for pattern in PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True, pattern

    return False, None


def main():
    print(" XSS Watcher started — monitoring access.log...")
    print("=" * 60)

    last_position = 0

    while True:
        try:
            if not os.path.exists(LOG_PATH):
                time.sleep(1)
                continue

            with open(LOG_PATH, "r", encoding="utf-8") as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()

            for line in new_lines:
                is_xss, pattern = check_line(line)

                if is_xss:
                    print(" XSS ATTACK DETECTED!")
                    print(f"   Pattern: {pattern}")
                    print(f"   Line: {line.strip()}")
                    print("-" * 60)

                    with open("alerts.log", "a", encoding="utf-8") as f:
                        f.write(f"XSS DETECTED - Pattern: {pattern} - {line.strip()}\n")

            time.sleep(0.5)

        except Exception as e:
            print(f" Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()


   
