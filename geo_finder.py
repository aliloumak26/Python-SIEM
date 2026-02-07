import geoip2.database
import os
import random

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CITY_DB_PATH = os.path.join(BASE_DIR, 'data', 'GeoLite2-City.mmdb')

# Reader global pour la performance
_READER = None

def get_reader():
    global _READER
    if _READER is None and os.path.exists(CITY_DB_PATH):
        try:
            _READER = geoip2.database.Reader(CITY_DB_PATH)
        except Exception as e:
            print(f"[!] Erreur ouverture City DB: {e}")
    return _READER

def get_ip_info(ip):
    """
    Retourne les infos précises (Pays, Ville, Coordonnées) via GeoLite2-City.
    """
    info = {
        "country": "Unknown",
        "city": "Unknown",
        "coords": [0, 0],
        "iso": "?",
        "isp": "N/A" # Le fichier City ne contient pas l'ISP (il faut l'ASN pour ça)
    }

    if ip in ["127.0.0.1", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        info.update({"country": "Local", "city": "Local Network", "coords": [0, 0], "iso": "L"})
        return info

    try:
        reader = get_reader()
        if not reader:
            return info
            
        response = reader.city(ip)
        
        # Extraction des données précises
        info["country"] = response.country.name or "Unknown"
        info["iso"] = response.country.iso_code or "?"
        
        # Fallback pour la ville : City -> Subdivision (Région/État) -> Unknown
        if response.city.name:
            info["city"] = response.city.name
        elif response.subdivisions:
            info["city"] = response.subdivisions[0].name
        else:
            info["city"] = "Unknown"
        
        # Coordonnées réelles de la base City !
        lat = response.location.latitude
        lon = response.location.longitude
        
        if lat is not None and lon is not None:
            # Léger jitter pour éviter que plusieurs IPs d'une même ville soient empilées
            info["coords"] = [
                lat + random.uniform(-0.02, 0.02),
                lon + random.uniform(-0.02, 0.02)
            ]
        else:
            # Fallback coordonnées pays (très approximatif) si location est None
            # On reste sur [0,0] pour éviter de polluer la map avec des points faux
            # mais on pourrait utiliser une table si besoin.
            pass
            
    except Exception as e:
        # print(f"Debug Geo Error: {e}")
        pass

    return info

def close_reader():
    global _READER
    if _READER:
        _READER.close()
        _READER = None

if __name__ == "__main__":
    # Test avec des IPs connues
    test_ips = ["8.8.8.8", "105.101.10.1", "190.162.32.3"]
    for ip in test_ips:
        res = get_ip_info(ip)
        print(f"IP: {ip} -> {res['city']}, {res['country']} {res['coords']}")
    close_reader()