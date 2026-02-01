import os
import time
import threading
import json
from datetime import datetime, timedelta
from typing import List, Callable, Dict
from config.settings import settings
from core.alert_manager import AlertManager
# Database removed
from utils.chiffrer import chiffrer_donnees

class SIEMEngine:
    """
    Moteur central du SIEM
    Gère la surveillance des logs et la détection d'attaques
    """
    
    def __init__(self, detectors: List[Callable] = None):
        self.alert_manager = AlertManager()
        # db removed
        self.detectors = detectors or []
        self.running = False
        self.watcher_thread = None
        self.callbacks = {
            'new_alert': [],
            'stats_update': []
        }
    
    def register_detector(self, detector: Callable):
        """Enregistre un nouveau détecteur"""
        if detector not in self.detectors:
            self.detectors.append(detector)
    
    def on(self, event: str, callback: Callable):
        """Enregistre un callback pour un événement"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def emit(self, event: str, data):
        """Émet un événement"""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                try:
                    callback(data)
                except Exception as e:
                    print(f"[Engine] Erreur callback {event}: {e}")
    
    def start(self):
        """Démarre le moteur de surveillance"""
        if self.running:
            print("[Engine] Déjà en cours d'exécution")
            return
        
        self.running = True
        self.watcher_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.watcher_thread.start()
        print("[Engine] ✓ Moteur SIEM démarré")
    
    def stop(self):
        """Arrête le moteur"""
        self.running = False
        if self.watcher_thread:
            self.watcher_thread.join(timeout=2)
        print("[Engine] ✓ Moteur SIEM arrêté")
    
    def _watch_loop(self):
        """Boucle principale de surveillance des logs (Déchiffre les logs à la volée)"""
        log_path = settings.CHIFFRED_PATH or "chiffred.enc"
        last_pos = 0
        
        while self.running:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue
                
                with open(log_path, "rb") as f:
                    f.seek(last_pos)
                    
                    while True:
                        line = f.readline()
                        if not line or not self.running:
                            break
                        
                        if not line.strip():
                            continue
                        
                        # Déchiffrer la ligne
                        try:
                            from utils.dechiffrer import dechiffrer_donnees
                            log_line = dechiffrer_donnees(line)
                            if not log_line: continue
                            
                            # Passer la ligne à tous les détecteurs
                            for detector in self.detectors:
                                found, pattern, attack_type = detector(log_line)
                                
                                if found:
                                    # Enregistrer l'alerte (JSON dans alerts.log)
                                    # Note: log_alert returns just an ID now, so we read back the last line
                                    self.alert_manager.log_alert(attack_type, pattern, log_line)
                                    
                                    # Récupérer la dernière alerte pour l'UI
                                    latest_alerts = self.get_recent_alerts(limit=1)
                                    if latest_alerts:
                                        self.emit('new_alert', latest_alerts[0])
                                    
                                    # Statistiques
                                    self.emit('stats_update', self.get_statistics())
                                    
                                    # Une seule alerte par ligne
                                    break
                        except Exception as e:
                            print(f"[Engine] Erreur ligne: {e}")
                    
                    last_pos = f.tell()
                
                time.sleep(settings.SLEEP_INTERVAL)
            
            except Exception as e:
                print(f"[Engine] Erreur surveillance: {e}")
                time.sleep(1)
    
    def _read_all_alerts(self) -> List[Dict]:
        """Lit toutes les alertes du fichier"""
        alerts = []
        path = settings.ALERTS_LOG_PATH
        if not os.path.exists(path):
            return []
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            alerts.append(json.loads(line))
                        except:
                            pass
        except Exception as e:
            print(f"[Engine] Erreur lecture logs: {e}")
        return alerts

    def get_statistics(self) -> dict:
        """Récupère les statistiques depuis le fichier de log"""
        alerts = self._read_all_alerts()
        
        # Filtrer les 30 derniers jours pour les stats
        cutoff = datetime.now() - timedelta(days=30)
        recent_alerts = []
        
        stats_by_type = {}
        top_ips = {}
        
        for alert in alerts:
            # Parse timestamp if needed, currently string
            try:
                ts = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S")
                if ts > cutoff:
                    recent_alerts.append(alert)
                    
                    # Type count
                    atype = alert.get('attack_type', 'Unknown')
                    stats_by_type[atype] = stats_by_type.get(atype, 0) + 1
                    
                    # IP count
                    ip = alert.get('source_ip')
                    if ip and ip != 'unknown':
                        top_ips[ip] = top_ips.get(ip, 0) + 1
            except:
                continue
                
        total = len(recent_alerts)
        
        # Sort top IPs
        sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'by_type': stats_by_type,
            'total': total,
            'top_ips': [{"source_ip": ip, "count": c} for ip, c in sorted_ips]
        }
    
    def get_recent_alerts(self, limit: int = 100):
        """Récupère les alertes récentes (lecture inverse)"""
        alerts = []
        path = settings.ALERTS_LOG_PATH
        if not os.path.exists(path):
            return []
            
        # Lecture simple (optimisable avec seek pour gros fichiers)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in reversed(lines):
                    if len(alerts) >= limit:
                        break
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            alerts.append(json.loads(line))
                        except:
                            pass
        except Exception as e:
            print(f"[Engine] Erreur lecture logs: {e}")
            
        return alerts

    def get_honeypot_logs(self, limit: int = 100):
        """Récupère les logs honeypot récents (lecture inverse)"""
        logs = []
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "honeypot.log")
        
        if not os.path.exists(path):
            return []
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in reversed(lines):
                    if len(logs) >= limit:
                        break
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            logs.append(json.loads(line))
                        except:
                            pass
        except Exception as e:
            print(f"[Engine] Erreur lecture honeypot logs: {e}")
            
        return logs
