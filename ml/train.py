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

def generate_normal_logs(count: int = 1000) -> list:
    """Génère des logs HTTP normaux (Format Node.js unifié)"""
    logs = []
    
    endpoints = ["/api/teachers", "/api/students", "/api/classes", "/api/search", "/api/users"]
    methods = ["GET", "POST", "PUT"]
    
    for i in range(count):
        time_iso = f"2026-01-31T{random.randint(10,23)}:{random.randint(10,59)}:{random.randint(10,59)}.123Z"
        method = random.choice(methods)
        path = f"{random.choice(endpoints)}/{random.randint(1,100)}"
        
        body = ""
        if method in ["POST", "PUT"]:
            # On simule un formulaire complet comme celui de l'utilisateur
            first = random.choice(["Lyes", "Amine", "Sarah", "Karim", "Zouina", "Lyes"])
            last = random.choice(["Abada", "Ziri", "Belaid", "Doukha", "Merah"])
            grade = random.choice(["Maitre de conference", "Professeur", "1, Master Assistant"])
            gender = random.choice(["Man", "Woman"])
            email = f"{first.lower()}{random.randint(1,99)}@gmail.com"
            
            body = f' body:{{"lastName":"{last}","firstName":"{first}","grade":"{grade}","gender":"{gender}","phone":"0550{random.randint(100000,999999)}","email":"{email}","statut":"Actif"}}'
            
        status = 200
        duration = f"{random.randint(5, 40)}ms"
        
        log = f"[18:00:00] {time_iso}  ::1  {method} {path}{body}  {status}  {duration}"
        logs.append(log)
    
    return logs

def generate_attack_logs(count: int = 100) -> list:
    """Génère des logs d'attaques (Format Node.js unifié)"""
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
        time_iso = f"2026-01-31T20:00:00.000Z"
        method = random.choice(["GET", "POST"])
        payload = random.choice(attack_payloads)
        
        if method == "POST":
            path = "/api/login"
            body = f' body:{{"user":"admin","pass":"{payload}"}}'
        else:
            path = f"/api/search?q={payload}"
            body = ""
            
        log = f"[20:00:00] {time_iso}  ::1  {method} {path}{body}  200  15ms"
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
    # Forcer le chemin de sauvegarde absolu
    model_path = os.path.join(BASE_DIR, 'ml', 'anomaly_model.pkl')
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
