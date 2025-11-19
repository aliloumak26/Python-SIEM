import os
import time
from config.settings import settings
from core.alert_manager import AlertManager

from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss
from detectors.crlf import detect as detect_crlf
from detectors.bruteforce import detect as detect_bruteforce
from detectors.os_injection import detect as detect_os_injection


DETECTORS = [
    detect_sqli,
    detect_xss,
    detect_crlf,
    detect_bruteforce,
    detect_os_injection,
]

alert_manager = AlertManager()

def watch_access_log():
    log_path = settings.ACCESS_LOG_PATH
    last_pos = 0

    while True:
        if not os.path.exists(log_path):
            time.sleep(1)
            continue

        with open(log_path, "r", encoding="utf-8") as f:
            f.seek(last_pos)
            lines = f.readlines()
            last_pos = f.tell()

        for line in lines:
            for detector in DETECTORS:
                found, pattern, attack_type = detector(line)
                
                if found:
                    alert_manager.log_alert(attack_type, pattern, line)
                    alert_manager.print_alert(attack_type, pattern, line)

        time.sleep(settings.SLEEP_INTERVAL)
