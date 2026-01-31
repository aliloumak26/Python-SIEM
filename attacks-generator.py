#!/usr/bin/env python3
import random
import time
import threading
from config.settings import settings

LOG_PATH = settings.ACCESS_LOG_PATH

SQLI_PATTERNS = [

    # SELECT patterns
    r"select\s+\*?\s+from",
    r"select.*from.*where",
    r"select.*as",
    
    
    # UNION attacks
    r"union\s+select",
    r"union\s+all\s+select",
    r"union.*from",
    
    # DROP/DELETE
    r"drop\s+table",
    r"drop\s+database",
    r";\s*drop",
    r"delete\s+from",
    
    # INSERT/UPDATE
    r"insert\s+into",
    r"update\s+.*set",
    
    # Time-based
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"waitfor\s+delay",
    
    # System commands
    r"xp_cmdshell",
    r"exec\s+xp",
    r"execute\s+xp",
    
    # Comments
    r"--\s",
    r"#\s*$",
    r"/\*",
    r"\*/",
    
    # Stacked queries
    r";\s*select",
    r";\s*insert",
    r";\s*update",
    r";\s*delete",
    r";\s*exec",
    
    # Load file
    r"load_file\s*\(",
    r"into\s+outfile",
    r"into\s+dumpfile",
    
    # Boolean
    r"and\s+1\s*=\s*1",
    r"and\s+1\s*=\s*2",
    
    # Order by
    r"order\s+by",
    r"group\s+by",
    
    # Information schema
    r"information_schema",
    r"mysql\.user",
    r"sysobjects",
    
    # Hex encoding
    r"0x[0-9a-f]{2,}",
    
    # CASE/WHEN
    r"case\s+when",
    
    # Stored procedures
    r"exec\s*\(",
    r"execute\s*\(",
]

XSS_PATTERNS = [
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



# ----------------- LOG CREATOR -----------------
def generate_log_entry(attack_type, payload):
    # Format unifié (identique au logger Node.js)
    # ${timestamp}  ${ip}  ${req.method} ${req.originalUrl}${bodyString}  ${res.statusCode}  ${duration}ms
    
    from datetime import datetime
    timestamp = datetime.now().isoformat() + "Z"
    ip = "::1"
    
    # On simule parfois du POST/PUT pour inclure le payload dans le body
    method = random.choice(["GET", "POST", "PUT"])
    
    if method in ["POST", "PUT"]:
        path = "/api/teachers/1"
        body = f' body:{{"firstName":"LYES","lastName":"ABADA","payload":"{payload}"}}'
    else:
        path = f"/api/search?q={payload}"
        body = ""
        
    status = 200
    duration = f"{random.randint(5, 20)}ms"
    
    return f"{timestamp}  {ip}  {method} {path}{body}  {status}  {duration}\n"


# ----------------- ATTACK GENERATOR CLASS -----------------
class AttackGenerator:
    """Thread-safe attack generator that can be started and stopped."""
    
    def __init__(self, log_path=None, sleep_interval=5):
        """
        Initialize the attack generator.
        
        Args:
            log_path: Path to the log file (default: from settings)
            sleep_interval: Time between attacks in seconds
        """
        self.log_path = log_path or LOG_PATH
        self.sleep_interval = sleep_interval
        self.running = False
        self.thread = None
    
    def start(self):
        """Start the attack generator in a background thread."""
        if self.running:
            print("[!] Attack generator is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._generator_loop, daemon=True)
        self.thread.start()
        print("[+] Attack generator started")
    
    def stop(self):
        """Stop the attack generator gracefully."""
        if not self.running:
            print("[!] Attack generator is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[+] Attack generator stopped")
    
    def is_running(self):
        """Check if the generator is currently running."""
        return self.running
    
    def _generator_loop(self):
        """Main generator loop that runs in a background thread."""
        print("[+] Attack generator running...\n")
        
        while self.running:
            try:
                attack_type = random.choice(["SQL Injection", "XSS Injection"])
                
                if attack_type == "SQL Injection":
                    payload = random.choice(SQLI_PATTERNS)
                elif attack_type == "XSS Injection":
                    payload = random.choice(XSS_PATTERNS)
                
                log = generate_log_entry(attack_type, payload)
                
                # Chiffrer et écrire directement dans le fichier sécurisé
                try:
                    from utils.chiffrer import chiffrer_donnees
                    chiffrer_donnees(log)
                    print(f"[{attack_type}] (Chiffré) → {payload}")
                except Exception as e:
                    print(f"[!] Erreur chiffrement generator: {e}")
                
                time.sleep(self.sleep_interval)
                
            except Exception as e:
                print(f"[ERROR] Generator error: {e}")
                time.sleep(1)


# ----------------- LEGACY FUNCTION (for backward compatibility) -----------------
def start_attack_generator():
    """Legacy function - creates and runs generator indefinitely."""
    generator = AttackGenerator()
    generator.start()
    
    # Keep running until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        generator.stop()


if __name__ == "__main__":
    import threading
    start_attack_generator()
