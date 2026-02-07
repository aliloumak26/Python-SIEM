#!/usr/bin/env python3
import random
import time
import threading
from datetime import datetime
from config.settings import settings

LOG_PATH = settings.ACCESS_LOG_PATH

# =========================================================================================
#  REAL ATTACK PAYLOADS (Not Regex!)
#  Ces payloads sont conçus pour être détectés par les regex du dossier /detectors
# =========================================================================================

# =========================================================================================
#  SIGNATURE-BASED PAYLOADS (Détéctables par les RegEx du dossier /detectors)
# =========================================================================================

SIGNATURE_PAYLOADS = {
    "SQL Injection": [
        "' OR 1=1 --", "' UNION SELECT NULL,username,password FROM users --",
        "1; DROP TABLE users", "1' AND SLEEP(5) --", "admin' #",
        "1' OR 'a'='a", "1' AND 1=1 --"
    ],
    "XSS Injection": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(1)",
        "'><script>alert(document.cookie)</script>"
    ],
    "OS Command Injection": [
        "; ls -la", "| cat /etc/passwd", "& whoami", "$(id)", "`whoami`",
        "&& net user", "| ping -c 1 127.0.0.1"
    ],
    "Path Traversal": [
        "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "../../.env", "/static/../../etc/hosts"
    ],
    "NoSQL Injection": [
        '{"$gt": ""}', '{"$ne": null}', '{"$where": "this.password.length > 0"}',
        '{"$regex": ".*"}'
    ]
}

# =========================================================================================
#  BEHAVIORAL PAYLOADS (Bypass RegEx - Détection ML Pure)
#  Conçus pour ne matcher AUCUNE regex de /detectors (Entropie élevée, brouillage)
# =========================================================================================

BEHAVIORAL_PAYLOADS = {
    "SQLi Bypass": [
        "'; DECLARE @Z VARCHAR(800); SET @Z=0x53454c4543542a; " + " /* " + "X" * 150 + " */",
        "'; IF(1=1) BEGIN DECLARE @Y NVARCHAR(100) = N'USR';" + " -- " + "Y" * 150,
        "'; EXEC(CONCAT(CHAR(115),CHAR(101),CHAR(108),CHAR(101),CHAR(99),CHAR(116),CHAR(32),CHAR(42)))"
    ],
    "XSS Bypass": [
        "<math><mi//onfocusin=confirm(1) tabindex=1>AUTO_FOCUS_TEST" + "<!-- " + "A" * 150 + " -->",
        "<body/onpageshow=prompt(1)>" + " <!-- " + "B" * 150 + " -->",
        "<details/open/onmousemove=confirm(1)>MOVEMOUSE" + " <!-- " + "C" * 150 + " -->"
    ],
    "RCE Bypass": [
        "$(printf '\\167\\150\\157\\141\\155\\151' | /usr/bin/env base64 -d)" + " # " + "R" * 150,
        "& {printf /etc/pass?wd}" + " # " + "E" * 150,
        "<?=`./local_binary`?>" + " /* " + "P" * 150 + " */"
    ],
    "Logic/Structure": [
        '{"__proto__": {"polluted": "yes", "config": {"internal": {"auth": "none", "token": "' + "T" * 200 + '"}}}}',
        '{"metadata": {"permissions": ["system_admin"], "flags": {"is_privileged": 1}, "uuid": "' + "u" * 250 + '"}}',
        "".join([chr(random.randint(1, 31)) for _ in range(120)]) + "!!!@@@###" + "B" * 250
    ]
}

# =========================================================================================
#  GENERATOR LOGIC
# =========================================================================================

def generate_random_ip():
    """Génère une adresse IP réaliste parmi plusieurs pays."""
    # Liste de préfixes IP associés à des pays (Approximation)
    prefixes = [
        "190.162.", "82.112.", "45.33.",  "172.217.", "216.58.", # USA / Diverse
        "105.101.", "197.112.", "41.201.", # DZ
        "31.13.", "185.60.", # Europe
        "103.21.", "111.90.", # Asie
        "184.150.", "192.197.", "99.224." # Canada
    ]
    return f"{random.choice(prefixes)}{random.randint(1,254)}.{random.randint(1,254)}"

def generate_log_entry(attack_type, payload):
    """
    Génère une ligne de log réaliste contenant l'attaque.
    Format unifié: TIMESTAMP  IP  METHOD URL BODY STATUS DURATION
    """
    timestamp = datetime.now().isoformat() + "Z"
    ip = generate_random_ip() if random.random() > 0.1 else "127.0.0.1"
    
    method = "GET"
    path = "/"
    body = ""
    status = 200
    
    # Détection de la catégorie pour le routage de l'URL
    if attack_type in ["SQL Injection", "SQLi Bypass"]:
        scenario = random.choice(["search", "login", "id"])
        if scenario == "search":
            path = f"/api/items?q={payload}"
        elif scenario == "login":
            method = "POST"
            path = "/api/auth/login"
            body = f' body:{{"username":"admin","password":"{payload}"}}'
        else:
            path = f"/api/users/{payload}"

    elif attack_type in ["XSS Injection", "XSS Bypass"]:
        if random.random() > 0.5:
            method = "POST"
            path = "/api/comments"
            body = f' body:{{"comment":"{payload}","user_id":12}}'
        else:
            path = f"/search?q={payload}"

    elif attack_type in ["OS Command Injection", "RCE Bypass"]:
        method = "POST"
        path = "/api/tools/ping"
        body = f' body:{{"host":"8.8.8.8{payload}"}}'

    elif attack_type == "Path Traversal":
        method = "GET"
        path = f"/api/files/download?file={payload}"

    elif attack_type == "NoSQL Injection":
        method = "POST"
        path = "/api/v1/query"
        body = f' body:{{"filter":{payload}}}'

    elif attack_type == "Brute Force":
        method = "POST"
        path = "/api/auth/login"
        pass_attempt = f"pass{random.randint(1000,9999)}"
        body = f' body:{{"username":"admin","password":"{pass_attempt}"}}'
        status = 401
    
    elif attack_type == "Logic/Structure":
        method = random.choice(["POST", "PUT", "PATCH"])
        path = f"/api/v2/{random.choice(['update', 'sync', 'patch', 'internal'])}"
        body = f' body:{payload}'

    duration = f"{random.randint(10, 500)}ms"
    return f"{timestamp}  {ip}  {method} {path}{body}  {status}  {duration}\n"


class AttackGenerator:
    """Générateur d'attaques thread-safe"""
    
    def __init__(self, log_path=None, sleep_interval=2):
        self.log_path = log_path or LOG_PATH
        self.sleep_interval = sleep_interval
        self.running = False
        self.thread = None
    
    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        print("[+] Générateur d'attaques démarré")
    
    def stop(self):
        if not self.running: return
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[-] Générateur d'attaques arrêté")
    
    def is_running(self):
        return self.running
    
    def _run_loop(self):
        # Liste pondérée : 50% Signatures / 40% Behavioral / 10% Normal
        attack_categories = [
            "SIGNATURE", "SIGNATURE", "SIGNATURE", "SIGNATURE", "SIGNATURE",
            "BEHAVIORAL", "BEHAVIORAL", "BEHAVIORAL", "BEHAVIORAL",
            "NORMAL"
        ]
        
        while self.running:
            try:
                category = random.choice(attack_categories)
                atype = ""
                payload = ""
                
                if category == "SIGNATURE":
                    atype = random.choice(list(SIGNATURE_PAYLOADS.keys()) + ["Brute Force"])
                    if atype == "Brute Force":
                        self._perform_brute_force_burst()
                        time.sleep(self.sleep_interval)
                        continue
                    payload = random.choice(SIGNATURE_PAYLOADS[atype])
                
                elif category == "BEHAVIORAL":
                    atype = random.choice(list(BEHAVIORAL_PAYLOADS.keys()))
                    payload = random.choice(BEHAVIORAL_PAYLOADS[atype])
                
                else: # NORMAL
                    atype = "Normal Traffic"
                    endpoints = ["/api/teachers", "/api/students", "/api/classes", "/api/search", "/api/users", "/home", "/dashboard"]
                    method = random.choice(["GET", "POST", "PUT"])
                    path = f"{random.choice(endpoints)}/{random.randint(1,100)}"
                    body = ""
                    if method in ["POST", "PUT"]:
                        first = random.choice(["Lyes", "Amine", "Sarah", "Karim", "Zouina"])
                        last = random.choice(["Abada", "Ziri", "Belaid", "Doukha"])
                        body = f' body:{{"name":"{first} {last}","action":"update"}}'
                    
                    timestamp = datetime.now().isoformat() + "Z"
                    duration = f"{random.randint(5, 50)}ms"
                    ip = generate_random_ip() if random.random() > 0.2 else "127.0.0.1"
                    log_line = f"{timestamp}  {ip}  {method} {path}{body}  200  {duration}\n"
                    self._write_log(log_line, "Normal Traffic", f"{method} {path}")
                    time.sleep(random.uniform(self.sleep_interval * 0.5, self.sleep_interval * 1.5))
                    continue

                # Générer et chiffrer le log
                log_line = generate_log_entry(atype, payload)
                self._write_log(log_line, atype, payload)
                
                time.sleep(random.uniform(self.sleep_interval * 0.5, self.sleep_interval * 1.5))
                
            except Exception as e:
                print(f"[ERROR] Generator Loop: {e}")
                time.sleep(1)

    def _perform_brute_force_burst(self):
        """Génère une rafale de 5 à 10 tentatives de login échouées"""
        count = random.randint(6, 12)
        print(f"[Brute Force] Rafale de {count} tentatives...")
        
        for _ in range(count):
            if not self.running: break
            
            log = generate_log_entry("Brute Force", "")
            self._write_log(log, "Brute Force", "WrongPassword")
            
            # Très rapide (< 1s entre chaque requête)
            time.sleep(random.uniform(0.1, 0.5))

    def _write_log(self, log_line, attack_type, payload):
        try:
            from utils.chiffrer import chiffrer_donnees
            chiffrer_donnees(log_line)
            # Affichage console pour debug
            short_payload = payload[:40] if payload else ""
            print(f"[{attack_type}] → {short_payload}...")
        except Exception as e:
            print(f"[!] Erreur écriture log: {e}")

# Compatibilité
def start_attack_generator():
    gen = AttackGenerator()
    gen.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        gen.stop()

if __name__ == "__main__":
    start_attack_generator()
