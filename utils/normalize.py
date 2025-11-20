import html
from urllib.parse import unquote

def normalize(text: str) -> str:
    if not text:
        return ""
    try:
        decoded = unquote(text)
<<<<<<< HEAD
        decoded =unquote(decoded)  # Pour double encodage 
        decoded = html.unescape(decoded) 
=======
        decoded =unquote(decoded)  # Decode twice to handle double-encoding
        decoded = html.unescape(decoded) #this one  for html entities
>>>>>>> 00a3af7d333a9ece957859fe69ef4ce0062163af
        decoded = decoded.encode('utf-8').decode('unicode_escape')
        decoded = decoded.replace('\\"', '"').replace("\\'", "'")
        decoded = decoded.replace("\\\\", "").replace("\\","")
        decoded = " ".join(decoded.split())
        return decoded.lower().strip()
    except:
        return text.lower().strip()