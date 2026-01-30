import os
import sys
from config.settings import settings
from utils.chiffrer import chiffrer_donnees
from utils.dechiffrer import dechiffrer_donnees
from detectors.sqli import detect as detect_sqli
from core.alert_manager import AlertManager

def test():
    test_file = "test_chiffre.enc"
    if os.path.exists(test_file):
        os.remove(test_file)
    
    payload = "127.0.0.1 - - [10/Feb/2025:10:10:10 +0100] \"GET /test?q=select * from users HTTP/1.1\" 200 123 \"-\" \"AttackBot\""
    print(f"[1] Original payload: {payload}")
    
    # 1. Chiffrer
    chiffrer_donnees(payload, test_file)
    print(f"[2] Encrypted and saved to {test_file}")
    
    # 2. Lire et déchiffrer
    with open(test_file, "rb") as f:
        encrypted_line = f.readline()
    
    decrypted = dechiffrer_donnees(encrypted_line)
    print(f"[3] Decrypted: {decrypted}")
    
    if decrypted.strip() == payload.strip():
        print("[OK] Decryption successful")
    else:
        print("[FAIL] Decryption failed or mismatch")
        return

    # 3. Détecter
    found, patterns, attack_type = detect_sqli(decrypted)
    print(f"[4] Detection: found={found}, type={attack_type}")
    
    if found:
        # 4. Logger alerte
        am = AlertManager()
        alert_id = am.log_alert(attack_type, patterns, decrypted)
        print(f"[5] Alert logged, ID: {alert_id}")
        
        # Vérifier alerts.log
        with open(settings.ALERTS_LOG_PATH, "r", encoding="utf-8") as f:
            last_lines = f.readlines()[-1:]
            print(f"[6] Last line in alerts.log: {last_lines}")
    else:
        print("[FAIL] Attack not detected")

if __name__ == "__main__":
    test()
