#!/usr/bin/env python3
"""
SIEM Professional - Main Launcher
Lance tous les composants du système SIEM
"""

import sys
import os
import time
import threading
import webbrowser
import uvicorn
from pathlib import Path

# Ajouter le répertoire au path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import SIEMEngine
# Database removed
from honeypot.ssh_honeypot import SSHHoneypot, HTTPHoneypot
from api.main import app

# Détecteurs
from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss
from detectors.bruteforce import detect as detect_bruteforce
from detectors.csrf import detect as detect_csrf
from detectors.file_upload import detect as detect_file_upload
from detectors.os_injection import detect as detect_os_injection
from detectors.crlf import detect as detect_crlf

class SIEMSystem:
    """Système SIEM complet"""
    
    def __init__(self):
        self.engine = None
        self.ssh_honeypot = None
        self.http_honeypot = None
        self.api_thread = None
        
        # Base de données retirée
        print("[SIEM] ✓ Système initialisé (Mode Fichier)")
    
    def start(self):
        """Démarre tous les composants"""
        print("\n" + "="*60)
        print("🛡️  SIEM PROFESSIONNEL - DÉMARRAGE")
        print("="*60 + "\n")
        
        # 1. Démarrer le moteur SIEM
        print("[1/4] Démarrage du moteur SIEM...")
        detectors = [detect_sqli, detect_xss, detect_bruteforce, detect_csrf, detect_file_upload, detect_os_injection, detect_crlf]
        self.engine = SIEMEngine(detectors=detectors)
        self.engine.start()
        
        # 2. Démarrer les honeypots
        print("[2/4] Démarrage des honeypots...")
        self.ssh_honeypot = SSHHoneypot(host='0.0.0.0', port=2222)
        self.ssh_honeypot.start()
        
        self.http_honeypot = HTTPHoneypot(host='0.0.0.0', port=8888)
        self.http_honeypot.start()
        
        # 3. Démarrer l'API FastAPI
        print("[3/4] Démarrage de l'API web...")
        self.api_thread = threading.Thread(
            target=self._run_api,
            daemon=True
        )
        self.api_thread.start()
        
        # Attendre que l'API démarre
        time.sleep(2)
        
        # 4. Ouvrir le navigateur
        print("[4/4] Ouverture du dashboard...")
        webbrowser.open('http://localhost:8000')
        
        print("\n" + "="*60)
        print("✅ SYSTÈME OPÉRATIONNEL")
        print("="*60)
        print("\n📊 Dashboard:      http://localhost:8000")
        print("🔌 API:            http://localhost:8000/api/stats")
        print("🍯 SSH Honeypot:   localhost:2222")
        print("🍯 HTTP Honeypot:  localhost:8888")
        print("\n💡 Utilisez attacks-generator.py pour générer des attaques")
        print("💡 Appuyez sur Ctrl+C pour arrêter\n")
        print("="*60 + "\n")
        
        # Garder le programme actif
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def _run_api(self):
        """Exécute l'API FastAPI"""
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            access_log=False
        )
    
    def stop(self):
        """Arrête tous les composants"""
        print("\n\n" + "="*60)
        print("🛑 ARRÊT DU SYSTÈME")
        print("="*60 + "\n")
        
        if self.engine:
            self.engine.stop()
        
        if self.ssh_honeypot:
            self.ssh_honeypot.stop()
        
        if self.http_honeypot:
            self.http_honeypot.stop()
        
        print("\n✅ Système arrêté proprement")
        print("="*60 + "\n")
        sys.exit(0)


def main():
    """Point d'entrée principal"""
    
    # Vérifier si on doit entraîner le modèle ML
    ml_model_path = os.path.join(os.path.dirname(__file__), 'ml', 'anomaly_model.pkl')
    
    if not os.path.exists(ml_model_path):
        print("\n⚠️  Modèle ML non trouvé!")
        print("💡 Lancez d'abord: python ml/train.py\n")
        response = input("Voulez-vous entraîner le modèle maintenant? (o/n): ")
        
        if response.lower() == 'o':
            print("\nEntraînement du modèle ML...")
            from ml import train
            train.main()
            print("\n✅ Modèle entraîné!")
            time.sleep(2)
    
    # Démarrer le système
    system = SIEMSystem()
    system.start()


if __name__ == "__main__":
    main()
