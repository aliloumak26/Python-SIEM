import os
from dotenv import load_dotenv

load_dotenv()  

class Settings:
    ACCESS_LOG_PATH = os.getenv("ACCESS_LOG_PATH")
    ALERTS_LOG_PATH = os.getenv("ALERTS_LOG_PATH")
    SLEEP_INTERVAL = float(os.getenv("SLEEP_INTERVAL", 0.5))
    FERNET_KEY = os.getenv("FERNET_KEY")
    CHIFFRED_PATH = os.getenv("CHIFFRED_PATH")
settings = Settings()
