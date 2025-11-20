from cryptography.fernet import Fernet
import sys , os

# Ajouter le chemin parent pour importer config.settings
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config.settings import settings

key = settings.FERNET_KEY.encode()
fernet = Fernet(key)

def comparer_fichiers(f1, f2):
    with open(f1, "rb") as a, open(f2, "rb") as b:
        return a.read() == b.read()

def dechiffrer_fichier(src):
    with open(src, "rb") as f:
        data = f.read()
    decrypted = fernet.decrypt(data)
    return decrypted.decode("utf-8", errors="ignore")
    
    

