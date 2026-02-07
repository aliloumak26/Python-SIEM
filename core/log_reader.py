import os
import time
from config.settings import settings
from core.alert_manager import AlertManager
from utils.dechiffrer import dechiffrer_fichier

from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss
from detectors.crlf import detect as detect_crlf
from detectors.bruteforce import detect as detect_bruteforce
from detectors.os_injection import detect as detect_os_injection
from detectors.file_upload import detect as detect_file_upload
from detectors.csrf import detect as detect_csrf

DETECTORS = [
    detect_sqli,
    detect_xss,
    detect_crlf,
    detect_bruteforce,
    detect_os_injection,
    detect_file_upload,
    detect_csrf
]

alert_manager = AlertManager()
chiffred_path = settings.CHIFFRED_PATH

def watch_access_log():
    error_count = 0
    max_errors_before_skip = 3 
    
    while True:
        if not os.path.exists(chiffred_path):
            time.sleep(1)
            continue

        try:
            if os.path.getsize(chiffred_path) == 0:
                time.sleep(settings.SLEEP_INTERVAL)
                continue

            decrypted_text = dechiffrer_fichier(chiffred_path)
            
            if not decrypted_text.strip():
                with open(chiffred_path, "wb") as f:
                    f.write(b"")
                time.sleep(settings.SLEEP_INTERVAL)
                continue
                
            lines = decrypted_text.splitlines()
            
            # print(f"📖 Traitement de {len(lines)} logs...")
            
            for line in lines:
                for detector in DETECTORS:
                    found, pattern, attack_type = detector(line)
                    if found:
                        alert_manager.log_alert(attack_type, pattern, line)
                        alert_manager.print_alert(attack_type, pattern, line)

            # vider
            with open(chiffred_path, "wb") as f:
                f.write(b"")
            
            error_count = 0  

        except Exception as e:
            error_count += 1
            # print(f" Erreur ({error_count}/{max_errors_before_skip}) lors du traitement: {e}")
            
            if error_count >= max_errors_before_skip:
                # Trop d'erreurs, on vide le fichier pour éviter une boucle infinie
                # print(" Trop d'erreurs, vidage du fichier pour éviter la boucle")
                try:
                    with open(chiffred_path, "wb") as f:
                        f.write(b"")
                    error_count = 0  
                except:
                    pass

        time.sleep(settings.SLEEP_INTERVAL)
