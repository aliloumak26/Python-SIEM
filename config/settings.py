import os

class Settings:
    ACCESS_LOG_PATH = os.environ.get(
        "ACCESS_LOG_PATH",
        r"C:\Users\sramz\Desktop\PFC\backend-project\access.log"
    )
    ALERTS_LOG_PATH = os.environ.get(
        "ALERTS_LOG_PATH",
        "logs/alerts.log"
    )
    SLEEP_INTERVAL = float(os.environ.get("SLEEP_INTERVAL", 0.5)) 

settings = Settings()
