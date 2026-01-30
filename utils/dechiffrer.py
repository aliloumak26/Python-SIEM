from cryptography.fernet import Fernet
import sys , os

# Ajouter le chemin parent pour importer config.settings
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config.settings import settings

key = settings.FERNET_KEY.encode()
fernet = Fernet(key)

def dechiffrer_fichier(src):
    """Déchiffre un fichier complet (format ligne par ligne)"""
    if not os.path.exists(src):
        return ""
    
    results = []
    with open(src, "rb") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                decrypted = fernet.decrypt(line)
                results.append(decrypted.decode("utf-8", errors="ignore"))
            except Exception as e:
                print(f"[Crypto] Erreur ligne: {e}")
    
    return "\n".join(results)

def dechiffrer_donnees(encrypted_data: bytes) -> str:
    """Déchiffre un bloc de données (ligne unique)"""
    try:
        decrypted = fernet.decrypt(encrypted_data.strip())
        return decrypted.decode("utf-8", errors="ignore")
    except:
        return ""

