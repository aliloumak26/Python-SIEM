import os
from dotenv import load_dotenv

load_dotenv()  

class Settings:
    ACCESS_LOG_PATH = os.environ.get(
        "ACCESS_LOG_PATH",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "access.log")
    )
    ALERTS_LOG_PATH = os.environ.get(
        "ALERTS_LOG_PATH",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "alerts.log")
    )
    SLEEP_INTERVAL = float(os.environ.get("SLEEP_INTERVAL", 0.5))
    FERNET_KEY = os.getenv("FERNET_KEY") 
    CHIFFRED_PATH = os.getenv("CHIFFRED_PATH", "chiffred.enc")
settings = Settings()
