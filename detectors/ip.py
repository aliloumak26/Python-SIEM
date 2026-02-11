import requests
import re
import time
from config.settings import settings

# Configuration
API_KEY = settings.API_KEY
URL = "https://api.abuseipdb.com/api/v2/check"
CONFIDENCE_THRESHOLD = 50  # Seuil pour déclencher une alerte

# Cache simple pour éviter les appels API répétés (IP: (score, expiry))
_cache = {}
CACHE_DURATION = 3600  # 1 heure

def detect_ip_reputation(log_line: str):
    """
    Détecteur de réputation IP utilisant AbuseIPDB.
    Retourne (found, pattern, attack_type)
    """
    if not API_KEY:
        return False, None, None

    # 1. Extraire l'IP (recherche du format standard IPv4)
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
    if not ip_match:
        return False, None, None
    
    ip_address = ip_match.group(1)

    # 2. Vérifier le cache
    now = time.time()
    if ip_address in _cache:
        score, expiry = _cache[ip_address]
        if now < expiry:
            if score >= CONFIDENCE_THRESHOLD:
                return True, f"AbuseIPDB Score: {score}%", "Malicious IP"
            return False, None, None

    # 3. Appeler l'API AbuseIPDB
    try:
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
        headers = {
            "Key": API_KEY,
            "Accept": "application/json"
        }
        
        response = requests.get(URL, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            
            # Mettre en cache
            _cache[ip_address] = (score, now + CACHE_DURATION)
            
            if score >= CONFIDENCE_THRESHOLD:
                return True, [f"AbuseIPDB Score: {score}%"], "Malicious IP"
        else:
            # En cas d'erreur (ex: quota dépassé), on met en cache un score de 0 
            # temporairement pour ne pas spammer en boucle l'erreur
            _cache[ip_address] = (0, now + 300) 
            
    except Exception as e:
        # print(f"[AbuseIPDB] Erreur: {e}")
        pass

    return False, None, None

# Pour test manuel rapide
if __name__ == "__main__":
    test_line = "2024-02-10T12:00:00Z  127.0.0.1  GET /"
    print(detect_ip_reputation(test_line))
