#!/usr/bin/env python3
"""
Script d'entraînement des modèles ML
Génère des données synthétiques et entraîne le détecteur d'anomalies
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml.anomaly_detector import AnomalyDetector
import random

def generate_normal_logs(count: int = 1000) -> list:
    """Génère des logs HTTP normaux"""
    logs = []
    
    normal_paths = [
        '/', '/index.html', '/about', '/contact', '/products', '/services',
        '/api/users', '/api/products', '/favicon.ico', '/robots.txt',
        '/css/style.css', '/js/app.js', '/images/logo.png'
    ]
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (X11; Linux x86_64)',
    ]
    
    status_codes = [200, 200, 200, 200, 304, 301, 302]  # Principalement 200
    
    for i in range(count):
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        path = random.choice(normal_paths)
        
        # Ajouter parfois des paramètres normaux
        if random.random() < 0.3:
            param_name = random.choice(['id', 'page', 'lang', 'sort'])
            param_value = random.randint(1, 100)
            path += f"?{param_name}={param_value}"
        
        method = random.choice(['GET', 'GET', 'GET', 'POST'])
        status = random.choice(status_codes)
        size = random.randint(100, 5000)
        agent = random.choice(user_agents)
        
        log = f'{ip} - - [10/Jan/2026:10:10:10 +0100] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'
        logs.append(log)
    
    return logs

def generate_attack_logs(count: int = 100) -> list:
    """Génère des logs d'attaques (pour tester)"""
    logs = []
    
    attack_payloads = [
        "' OR 1=1--",
        "UNION SELECT * FROM users",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "; DROP TABLE users;",
        "' AND 1=2 UNION SELECT NULL, username, password FROM admin--"
    ]
    
    for i in range(count):
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        payload = random.choice(attack_payloads)
        
        log = f'{ip} - - [10/Jan/2026:10:10:10 +0100] "GET /search?q={payload} HTTP/1.1" 200 123 "-" "AttackBot"'
        logs.append(log)
    
    return logs

def main():
    print("=" * 60)
    print("ENTRAÎNEMENT DES MODÈLES ML - SIEM")
    print("=" * 60)
    
    # Générer les données
    print("\n[1/3] Génération des données d'entraînement...")
    normal_logs = generate_normal_logs(2000)
    print(f"  ✓ {len(normal_logs)} logs normaux générés")
    
    # Entraîner le modèle
    print("\n[2/3] Entraînement du détecteur d'anomalies...")
    detector = AnomalyDetector()
    detector.train(normal_logs, contamination=0.05)
    
    # Sauvegarder
    print("\n[3/3] Sauvegarde du modèle...")
    detector.save_model()
    
    # Test rapide
    print("\n" + "=" * 60)
    print("TEST DU MODÈLE")
    print("=" * 60)
    
    test_normal = generate_normal_logs(10)
    test_attacks = generate_attack_logs(10)
    
    print("\nTest sur logs normaux:")
    normal_detected = 0
    for log in test_normal[:5]:
        is_anomaly, score = detector.predict(log)
        print(f"  {'⚠️ ANOMALIE' if is_anomaly else '✓ Normal'} (score: {score:.3f})")
        if is_anomaly:
            normal_detected += 1
    
    print("\nTest sur logs d'attaque:")
    attack_detected = 0
    for log in test_attacks[:5]:
        is_anomaly, score = detector.predict(log)
        print(f"  {'⚠️ ANOMALIE' if is_anomaly else '✓ Normal'} (score: {score:.3f})")
        if is_anomaly:
            attack_detected += 1
    
    print("\n" + "=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)
    print(f"Faux positifs: {normal_detected}/5 logs normaux détectés comme anomalies")
    print(f"Vrais positifs: {attack_detected}/5 attaques détectées")
    print("\n✓ Entraînement terminé avec succès!")
    print("=" * 60)

if __name__ == "__main__":
    main()
