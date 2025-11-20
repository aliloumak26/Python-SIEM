from cryptography.fernet import Fernet
from settings import settings
import sys
import os

key = settings.FERNET_KEY.encode()
fernet = Fernet(key)

def chiffrer_stdin():
    dest = "chiffred.enc"
    
    # Lire les données depuis stdin
    data = sys.stdin.read().encode()
    
    # Si le fichier chiffré existe déjà, on déchiffre et on ajoute
    if os.path.exists(dest):
        with open(dest, "rb") as f:
            encrypted_existing = f.read()
        try:
            decrypted_existing = fernet.decrypt(encrypted_existing)
            # Concaténer anciennes données + nouvelles
            data = decrypted_existing + data
        except:
            pass

    encrypted = fernet.encrypt(data)
    
    with open(dest, "wb") as f:
        f.write(encrypted)

def main():
    chiffrer_stdin()

if __name__ == "__main__":
    main()
