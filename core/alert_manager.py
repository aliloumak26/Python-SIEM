import os
import datetime
import re
import json
from config.settings import settings
from utils.geoip import GeoIPLocator
from utils.chiffrer import chiffrer_donnees

class AlertManager:
    """Gestionnaire d'alertes avec base de données et géolocalisation"""
    
    def __init__(self):
        self.alert_log_path = settings.ALERTS_LOG_PATH
        # Database removed
        self.geoip = GeoIPLocator()
        
        # Créer le fichier de log si nécessaire
        if not os.path.exists(self.alert_log_path):
            with open(self.alert_log_path, "w", encoding="utf-8") as f:
                f.write("---- ALERT LOG ----\n")
    def calculate_severity(self, attack_type: str, pattern: str = None) -> str:
        """Calcule la sévérité d'une attaque"""
        critical_patterns = ['drop table', 'drop database', 'xp_cmdshell', 'exec']
        high_patterns = ['union select', 'insert into', 'delete from']
        
        if pattern:
            pattern_lower = pattern.lower()
            if any(p in pattern_lower for p in critical_patterns):
                return 'critical'
            if any(p in pattern_lower for p in high_patterns):
                return 'high'
        
        # Par type
        severity_map = {
            'SQL Injection': 'high',
            'XSS': 'medium',
            'XSS injection': 'medium',
            'Brute Force': 'medium',
            'HTTP Error': 'low'
        }
        
        return severity_map.get(attack_type, 'medium')
    
    def extract_ip(self, line: str) -> str:
        """Extrait l'IP source d'une ligne de log"""
        # Format Apache: IP - - [timestamp] ...
        match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)
        
        # Format alternatif
        match = re.search(r'-\s*([0-9a-fA-F\:\\.]+)\s*-\s*', line)
        if match:
            return match.group(1)
        
        return 'unknown'
    
    
    def log_alert(self, attack_type: str, pattern: str, line: str, 
                  ml_score: float = None, confidence: float = 1.0):
        """
        Enregistre une alerte dans le fichier de log au format JSON
        """
        # Convert list of patterns to string if necessary
        if isinstance(pattern, list):
            pattern = ", ".join(str(p) for p in pattern)
            
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Extraction IP
        source_ip = self.extract_ip(line)
        
        # Géolocalisation
        geo_data = None
        if source_ip != 'unknown':
            geo_data = self.geoip.locate(source_ip)
        
        # Calcul de sévérité
        severity = self.calculate_severity(attack_type, pattern)
        
        # Construction de l'objet alerte
        alert_data = {
            "id": int(datetime.datetime.now().timestamp() * 1000), # ID unique basé sur timestamp
            "timestamp": timestamp,
            "attack_type": attack_type,
            "severity": severity,
            "pattern": pattern,
            "source_ip": source_ip,
            "country": geo_data.get('country') if geo_data else None,
            "city": geo_data.get('city') if geo_data else None,
            "latitude": geo_data.get('latitude') if geo_data else None,
            "longitude": geo_data.get('longitude') if geo_data else None,
            "log_line": line.strip(),
            "ml_score": ml_score,
            "confidence": confidence
        }
        
        # Écriture dans le fichier (JSON Lines)
        # Note: On utilise 'a' pour append
        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_data) + "\n")
                f.flush()
                # os.fsync(f.fileno()) # Optionnel, peut ralentir
            print(f"[AlertManager] Alert logged to file (JSON)")
        except Exception as e:
            print(f"[AlertManager] FAILED to write to alerts.log: {e}")
            
        return alert_data["id"]
    
    def print_alert(self, attack_type: str, pattern: str, line: str):
        """Affiche une alerte (pour debug)"""
        print("⚠️ ALERT ⚠️")
        print(f"Type    : {attack_type}")
        print(f"Pattern : {pattern}")
        print(f"Line    : {line.strip()}")
        print("-" * 60)


