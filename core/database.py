import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from config.settings import settings

class Database:
    """Gestionnaire de base de données SQLite pour le SIEM"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "siem.db")
        self.db_path = db_path
        self.init_database()
    
    def get_connection(self):
        """Crée une connexion à la base de données"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Pour accéder aux colonnes par nom
        return conn
    
    def init_database(self):
        """Initialise le schéma de la base de données"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Table des alertes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                pattern TEXT,
                source_ip TEXT,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                log_line TEXT,
                ml_score REAL,
                confidence REAL DEFAULT 1.0
            )
        ''')
        
        # Table des logs honeypot
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS honeypot_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                username TEXT,
                password TEXT,
                command TEXT,
                country TEXT,
                city TEXT
            )
        ''')
        
        # Table des statistiques (agrégées par jour/type)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                UNIQUE(date, attack_type)
            )
        ''')
        
        # Index pour performances
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(attack_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_honeypot_timestamp ON honeypot_logs(timestamp)')
        
        conn.commit()
        conn.close()
    
    # ==================== ALERTS ====================
    
    def insert_alert(self, attack_type: str, pattern: str, source_ip: str, 
                    log_line: str, severity: str = 'medium', 
                    ml_score: float = None, confidence: float = 1.0,
                    geo_data: Dict = None) -> int:
        """Insère une nouvelle alerte"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        country = geo_data.get('country') if geo_data else None
        city = geo_data.get('city') if geo_data else None
        latitude = geo_data.get('latitude') if geo_data else None
        longitude = geo_data.get('longitude') if geo_data else None
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, attack_type, severity, pattern, source_ip, 
                              country, city, latitude, longitude, log_line, ml_score, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, attack_type, severity, pattern, source_ip, 
              country, city, latitude, longitude, log_line, ml_score, confidence))
        
        alert_id = cursor.lastrowid
        
        # Mettre à jour les statistiques
        date = datetime.now().strftime("%Y-%m-%d")
        cursor.execute('''
            INSERT INTO statistics (date, attack_type, count)
            VALUES (?, ?, 1)
            ON CONFLICT(date, attack_type) DO UPDATE SET count = count + 1
        ''', (date, attack_type))
        
        conn.commit()
        conn.close()
        return alert_id
    
    def get_recent_alerts(self, limit: int = 100, attack_type: str = None) -> List[Dict]:
        """Récupère les alertes récentes"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if attack_type:
            cursor.execute('''
                SELECT * FROM alerts 
                WHERE attack_type = ?
                ORDER BY id DESC LIMIT ?
            ''', (attack_type, limit))
        else:
            cursor.execute('''
                SELECT * FROM alerts 
                ORDER BY id DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_alerts_count(self) -> int:
        """Compte total des alertes"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_stats_by_type(self, days: int = 7) -> Dict[str, int]:
        """Statistiques par type d'attaque sur N jours"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT attack_type, SUM(count) as total
            FROM statistics
            WHERE date >= date('now', '-' || ? || ' days')
            GROUP BY attack_type
        ''', (days,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return {row['attack_type']: row['total'] for row in rows}
    
    # ==================== HONEYPOT ====================
    
    def insert_honeypot_log(self, service: str, source_ip: str, 
                           source_port: int = None,
                           username: str = None, password: str = None,
                           command: str = None, geo_data: Dict = None) -> int:
        """Insère un log honeypot"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        country = geo_data.get('country') if geo_data else None
        city = geo_data.get('city') if geo_data else None
        
        cursor.execute('''
            INSERT INTO honeypot_logs (timestamp, service, source_ip, source_port,
                                      username, password, command, country, city)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, service, source_ip, source_port, username, password, command, country, city))
        
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id
    
    def get_recent_honeypot_logs(self, limit: int = 100, service: str = None) -> List[Dict]:
        """Récupère les logs honeypot récents"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if service:
            cursor.execute('''
                SELECT * FROM honeypot_logs 
                WHERE service = ?
                ORDER BY id DESC LIMIT ?
            ''', (service, limit))
        else:
            cursor.execute('''
                SELECT * FROM honeypot_logs 
                ORDER BY id DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    # ==================== ANALYTICS ====================
    
    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Top IPs attaquantes"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM alerts
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [(row['source_ip'], row['count']) for row in rows]
    
    def get_attack_timeline(self, hours: int = 24) -> List[Dict]:
        """Timeline des attaques"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                attack_type,
                COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
            GROUP BY hour, attack_type
            ORDER BY hour
        ''', (hours,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_geo_data(self) -> List[Dict]:
        """Données géographiques pour la carte"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT country, city, latitude, longitude, COUNT(*) as count
            FROM alerts
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            GROUP BY country, city, latitude, longitude
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def clear_old_data(self, days: int = 30):
        """Nettoie les anciennes données"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM alerts 
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        
        cursor.execute('''
            DELETE FROM honeypot_logs 
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (days,))
        
        conn.commit()
        conn.close()
