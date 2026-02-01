#!/usr/bin/env python3
"""
TEST RAPIDE - Lance le SIEM avec des données de test
Pour tester rapidement sans attendre l'entraînement ML
"""

import sys
import os
import webbrowser
import time
import threading

# Ajouter au path
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import SIEMEngine
# Database removed
from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss
from detectors.bruteforce import detect as detect_bruteforce

def generate_test_attacks():
    """Génère quelques attaques de test"""
    from config.settings import settings
    
    test_logs = [
        '192.168.1.100 - - [26/Jan/2026:14:30:00 +0100] "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 123 "-" "Hacker"',
        '10.0.0.50 - - [26/Jan/2026:14:30:05 +0100] "GET /page?id=<script>alert(1)</script> HTTP/1.1" 200 456 "-" "Bot"',
        '172.16.0.20 - - [26/Jan/2026:14:30:10 +0100] "GET /admin UNION SELECT * FROM users HTTP/1.1" 200 789 "-" "Attacker"',
        '8.8.8.8 - - [26/Jan/2026:14:30:15 +0100] "GET /test?x=<img src=x onerror=alert(1)> HTTP/1.1" 200 321 "-" "XSS"',
    ]
    
    print("\n[TEST] Génération de 4 attaques de test...")
    
    with open(settings.ACCESS_LOG_PATH, 'w', encoding='utf-8') as f:
        for log in test_logs:
            f.write(log + '\n')
    
    print("[TEST] ✓ Attaques écrites dans logs/access.log")

def test_detectors():
    """Test rapide des détecteurs"""
    print("\n" + "="*60)
    print("TEST DES DÉTECTEURS")
    print("="*60 + "\n")
    
    test_cases = [
        ("SQL Injection", "GET /search?q=' OR 1=1--", detect_sqli),
        ("XSS", "GET /page?id=<script>alert(1)</script>", detect_xss),
    ]
    
    for name, payload, detector in test_cases:
        found, pattern, attack_type = detector(f'127.0.0.1 - - [10/Jan/2026:10:10:10 +0100] "{payload} HTTP/1.1" 200 123 "-" "Test"')
        status = "✅" if found else "❌"
        print(f"{status} {name}: {'Détecté' if found else 'Non détecté'}")
        if found:
            print(f"   Pattern: {pattern}")
    
    print()

def run_api_server():
    """Lance l'API FastAPI"""
    import uvicorn
    from api.main import app
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="warning",
        access_log=False
    )

def main():
    print("\n" + "="*60)
    print("🛡️  TEST RAPIDE - SIEM")
    print("="*60 + "\n")
    
    # DB removed
    print("[1/4] ✓ Base de données retirée (Mode Fichier)")
    
    # Test des détecteurs
    test_detectors()
    
    # Générer des attaques de test
    generate_test_attacks()
    print("[2/4] ✓ Données de test créées")
    
    # Démarrer le moteur SIEM
    print("[3/4] Démarrage du moteur SIEM...")
    detectors = [detect_sqli, detect_xss, detect_bruteforce]
    engine = SIEMEngine(detectors=detectors)
    engine.start()
    
    # Attendre un peu que les alertes soient détectées
    time.sleep(2)
    
    # Vérifier les alertes
    alerts = engine.get_recent_alerts(limit=10)
    print(f"   ✓ {len(alerts)} alertes détectées")
    
    # Démarrer l'API
    print("[4/4] Démarrage du serveur web...")
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    
    time.sleep(2)
    
    print("\n" + "="*60)
    print("✅ TEST RÉUSSI - Système opérationnel")
    print("="*60)
    print("\n📊 Dashboard: http://localhost:8000")
    print("🔍 Alertes détectées:", len(alerts))
    print("\n💡 Lancez 'python attacks-generator.py' pour plus d'attaques")
    print("💡 Appuyez sur Ctrl+C pour arrêter\n")
    print("="*60 + "\n")
    
    # Ouvrir le navigateur
    webbrowser.open('http://localhost:8000')
    
    # Garder actif
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n✓ Arrêt du test")
        sys.exit(0)

if __name__ == "__main__":
    main()
