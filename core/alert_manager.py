import os
import datetime
from config.settings import settings

class AlertManager:
    def __init__(self):

        self.alert_log_path = settings.ALERTS_LOG_PATH
        if not os.path.exists(self.alert_log_path):
            with open(self.alert_log_path, "w", encoding="utf-8") as f:
                f.write("---- ALERT LOG ----\n")

    def log_alert(self, attack_type, pattern, line):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {attack_type} detected | Pattern: {pattern} | Line: {line.strip()}\n"
        with open(self.alert_log_path, "a", encoding="utf-8") as f:
            f.write(entry)

    def print_alert(self, attack_type, pattern, line):
        print("⚠️ ALERT ⚠️")
        print(f"Type    : {attack_type}")
        print(f"Pattern : {pattern}")
        print(f"Line    : {line.strip()}")
        print("-" * 60)

