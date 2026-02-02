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

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    # "' OR 'a'='a",
    # "admin' --",
    "' UNION SELECT 1, username, password FROM users --",
    "' UNION ALL SELECT NULL, NULL, NULL --",
    "1; DROP TABLE users",
    "1'; DELETE FROM accounts --",
    "1 AND 1=1",
    "1' AND SLEEP(5) --",
    "1' WAITFOR DELAY '0:0:5' --",
    # "admin' #",
    "1' OR 1=1; EXEC xp_cmdshell('whoami') --",
    "%27%20OR%201%3D1%20--",  # URL Encoded
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "\";alert(1)//",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E", # URL Encoded
]

OS_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "; ping -c 1 127.0.0.1",
    "`id`",
    "$(whoami)",
    "&& net user",
    "| shutdown -r now",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../windows/win.ini",
    "....//....//etc/shadow",
    "/var/www/html/../../../etc/hosts",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

# =========================================================================================
#  ZERO-DAY PAYLOADS (Pour détection ML uniquement)
#  Ces attaques ne correspondent à AUCUNE regex connue, mais ont des caractéristiques statistiques anormales
# =========================================================================================

ZERO_DAY_PAYLOADS = [
    # 1. BUFFER OVERFLOW (Trop long > 1000 chars) du bruit aléatoire
    "A" * 1500,
    
    # 2. SSTI (Server Side Template Injection) - Beaucoup de caractères spéciaux { } _
    "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
    "{{7*7}}",
    
    # 3. NoSQL Injection (Structure JSON imbriquée avec $)
    'user[username][$ne]=admin&user[password][$ne]=admin',
    '{"$gt": ""}',
    
    # 4. Obfuscation extrême (Entropie élevée)
    "".join([chr(random.randint(33, 126)) for _ in range(100)]),
    
    # 5. Entêtes HTTP mal formés ou verbes inconnus (simulés dans log)
    "WEIRD_VERB",
]

# =========================================================================================
#  GENERATOR LOGIC
# =========================================================================================

def generate_log_entry(attack_type, payload):
    """
    Génère une ligne de log réaliste contenant l'attaque.
    Format unifié: TIMESTAMP  IP  METHOD URL BODY STATUS DURATION
    """
    timestamp = datetime.now().isoformat() + "Z"
    ip = "::1" # Localhost
    
    # 1. Déterminer le contexte (URL, Méthode) selon le type d'attaque
    method = "GET"
    path = "/"
    body = ""
    status = 200
    
    if attack_type == "SQL Injection":
        # Souvent dans des paramètres de recherche ou de login
        scenario = random.choice(["search", "login", "id"])
        if scenario == "search":
            method = "GET"
            path = f"/api/items?q={payload}"
        elif scenario == "login":
            method = "POST"
            path = "/api/auth/login"
            body = f' body:{{"username":"admin","password":"{payload}"}}'
        elif scenario == "id":
            method = "GET"
            path = f"/api/users/{payload}"

    elif attack_type == "XSS Injection":
        # Souvent dans des formulaires de contact ou commentaires
        method = random.choice(["POST", "GET"])
        if method == "POST":
            path = "/api/comments"
            body = f' body:{{"comment":"{payload}","user_id":12}}'
        else:
            path = f"/search?q={payload}"

    elif attack_type == "OS Command Injection":
        # Souvent dans des outils de ping ou de traitement de fichiers
        method = "POST"
        path = "/api/tools/ping"
        body = f' body:{{"host":"8.8.8.8{payload}"}}'

    elif attack_type == "Path Traversal":
        method = "GET"
        path = f"/api/files/download?file={payload}"

    elif attack_type == "Brute Force":
        # Brute force = échecs répétés
        method = "POST"
        path = "/api/auth/login"
        pass_attempt = f"pass{random.randint(1000,9999)}"
        body = f' body:{{"username":"admin","password":"{pass_attempt}"}}'
        status = 401 # Unauthorized
    
    elif attack_type == "Zero-Day Attack":
        # Anomalies statistiques pures
        if "A" * 1000 in payload: # Buffer Overflow
            method = "POST"
            path = "/api/upload"
            body = f' body:{{"data":"{payload}"}}'
        elif "{{" in payload: # SSTI
            method = "GET"
            path = f"/render?template={payload}"
        elif "WEIRD" in payload: # Verbe inconnu
            method = "SEARCH-ADMIN"
            path = "/secret"
        else:
            method = "POST"
            path = "/api/query"
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
        # Liste pondérée des attaques (plus de SQLi/XSS que de BruteForce complexe)
        attack_types = [
            "SQL Injection", "SQL Injection", 
            "XSS Injection", "XSS Injection",
            "OS Command Injection",
            "Path Traversal",
            "Brute Force",
            "Zero-Day Attack",
            "Normal Traffic", "Normal Traffic", "Normal Traffic", "Normal Traffic", "Normal Traffic" # ~40% de trafic normal
        ]
        
        while self.running:
            try:
                # Choisir un type d'attaque
                atype = random.choice(attack_types)
                payload = ""
                
                # Sélectionner le payload
                if atype == "SQL Injection":
                    payload = random.choice(SQLI_PAYLOADS)
                elif atype == "XSS Injection":
                    payload = random.choice(XSS_PAYLOADS)
                elif atype == "OS Command Injection":
                    payload = random.choice(OS_INJECTION_PAYLOADS)
                elif atype == "Path Traversal":
                    payload = random.choice(PATH_TRAVERSAL_PAYLOADS)
                elif atype == "Zero-Day Attack":
                    payload = random.choice(ZERO_DAY_PAYLOADS)
                elif atype == "Brute Force":
                    payload = "BRUTE_FORCE_MARKER" 
                    self._perform_brute_force_burst()
                    time.sleep(self.sleep_interval)
                    continue
                elif atype == "Normal Traffic":
                    # Génération de trafic normal (similaire à train.py)
                    endpoints = ["/api/teachers", "/api/students", "/api/classes", "/api/search", "/api/users", "/home", "/dashboard"]
                    methods = ["GET", "POST", "PUT"]
                    method = random.choice(methods)
                    path = f"{random.choice(endpoints)}/{random.randint(1,100)}"
                    body = ""
                    status = 200
                    
                    if method in ["POST", "PUT"]:
                        first = random.choice(["Lyes", "Amine", "Sarah", "Karim", "Zouina"])
                        last = random.choice(["Abada", "Ziri", "Belaid", "Doukha"])
                        body = f' body:{{"name":"{first} {last}","action":"update"}}'
                    
                    timestamp = datetime.now().isoformat() + "Z"
                    duration = f"{random.randint(5, 50)}ms"
                    log_line = f"{timestamp}  ::1  {method} {path}{body}  {status}  {duration}\n"
                    
                    self._write_log(log_line, "Normal Traffic", f"{method} {path}")
                    
                    sleep_time = random.uniform(self.sleep_interval * 0.5, self.sleep_interval * 1.5)
                    time.sleep(sleep_time)
                    continue

                # Générer et chiffrer le log
                log_line = generate_log_entry(atype, payload)
                self._write_log(log_line, atype, payload)
                
                # Pause avant la prochaine attaque
                sleep_time = random.uniform(self.sleep_interval * 0.5, self.sleep_interval * 1.5)
                time.sleep(sleep_time)
                
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
