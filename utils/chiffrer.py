from cryptography.fernet import Fernet
import sys
import os

# Ajouter le chemin parent pour importer config.settings
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config.settings import settings

key = settings.FERNET_KEY.encode()
fernet = Fernet(key)

def chiffrer_donnees(data_str: str, dest_file: str = None):
    """Chiffre une chaîne de caractères et l'ajoute comme une nouvelle ligne au fichier destination"""
    if dest_file is None:
        if hasattr(settings, 'CHIFFRED_PATH'):
            dest_file = settings.CHIFFRED_PATH
        else:
            dest_file = "chiffred.enc"
    
    # On s'assure que la donnée est sur une seule ligne pour le stockage
    data_str = data_str.strip().replace("\n", " ")
    encrypted = fernet.encrypt(data_str.encode())
    
    # On ajoute le log chiffré sur une nouvelle ligne (en base64/ascii pour être lisible par ligne)
    with open(dest_file, "ab") as f:
        f.write(encrypted + b"\n")

def main():
    # Lecture depuis stdin pour compatibilité avec l'ancien usage
    data = sys.stdin.read()
    if data:
        chiffrer_donnees(data)

if __name__ == "__main__":
    main()
