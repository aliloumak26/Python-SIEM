import os
import time
import threading
from typing import List, Callable
from config.settings import settings
from core.alert_manager import AlertManager
from core.database import Database
from utils.chiffrer import chiffrer_donnees

class SIEMEngine:
    """
    Moteur central du SIEM
    Gère la surveillance des logs et la détection d'attaques
    """
    
    def __init__(self, detectors: List[Callable] = None):
        self.alert_manager = AlertManager()
        self.db = Database()
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
                    # print(f"[Engine] Erreur callback {event}: {e}")
    
    def start(self):
        """Démarre le moteur de surveillance"""
        if self.running:
            # print("[Engine] Déjà en cours d'exécution")
            return
        
        self.running = True
        self.watcher_thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.watcher_thread.start()
        # print("[Engine] ✓ Moteur SIEM démarré")
    
    def stop(self):
        """Arrête le moteur"""
        self.running = False
        if self.watcher_thread:
            self.watcher_thread.join(timeout=2)
        # print("[Engine] ✓ Moteur SIEM arrêté")
    
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
                    
                    for line in f:
                        if not self.running:
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
                                    # Enregistrer l'alerte
                                    self.alert_manager.log_alert(attack_type, pattern, log_line)
                                    
                                    # Récupérer l'alerte complète depuis la DB
                                    alerts = self.db.get_recent_alerts(limit=1)
                                    if alerts:
                                        self.emit('new_alert', alerts[0])
                                    
                                    # Statistiques
                                    self.emit('stats_update', self.get_statistics())
                                    
                                    # Une seule alerte par ligne
                                    break
                        except Exception as e:
                            # print(f"[Engine] Erreur ligne: {e}")
                            

                    
                    last_pos = f.tell()
                
                time.sleep(settings.SLEEP_INTERVAL)
            
            except Exception as e:
                # print(f"[Engine] Erreur surveillance: {e}")
                time.sleep(1)
    
    def get_statistics(self) -> dict:
        """Récupère les statistiques actuelles"""
        stats_by_type = self.db.get_stats_by_type(days=30)
        total = sum(stats_by_type.values())
        
        return {
            'by_type': stats_by_type,
            'total': total,
            'top_ips': self.db.get_top_attackers(limit=10)
        }
    
    def get_recent_alerts(self, limit: int = 100):
        """Récupère les alertes récentes"""
        return self.db.get_recent_alerts(limit=limit)
