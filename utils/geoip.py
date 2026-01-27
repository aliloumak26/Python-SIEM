import requests
import time
from typing import Dict, Optional

class GeoIPLocator:
    """Module de géolocalisation IP avec cache"""
    
    def __init__(self):
        self.cache = {}
        self.api_url = "http://ip-api.com/json/{}"
        self.last_request_time = 0
        self.min_request_interval = 1.5  # Rate limit: max 45 req/min
    
    def locate(self, ip: str) -> Optional[Dict]:
        """
        Géolocalise une IP
        Retourne: {country, city, latitude, longitude} ou None
        """
        # IPs locales
        if ip.startswith(('127.', '192.168.', '10.', '172.')) or ip == 'localhost':
            return {
                'country': 'Local',
                'city': 'localhost',
                'latitude': 0.0,
                'longitude': 0.0
            }
        
        # Vérifier le cache
        if ip in self.cache:
            return self.cache[ip]
        
        # Rate limiting
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        
        try:
            response = requests.get(self.api_url.format(ip), timeout=3)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('lat', 0.0),
                        'longitude': data.get('lon', 0.0)
                    }
                    
                    # Mettre en cache
                    self.cache[ip] = geo_data
                    return geo_data
        
        except Exception as e:
            print(f"[GeoIP] Erreur pour {ip}: {e}")
        
        # Fallback
        fallback = {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0
        }
        self.cache[ip] = fallback
        return fallback
