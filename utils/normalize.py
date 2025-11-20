import html
from urllib.parse import unquote

def normalize(text: str) -> str:
    if not text:
        return ""
    try:
        decoded = unquote(text)
        decoded =unquote(decoded)  # Decode twice to handle double-encoding
        decoded = html.unescape(decoded) #this one  for html entities
        decoded = decoded.encode('utf-8').decode('unicode_escape')
        decoded = decoded.replace('\\"', '"').replace("\\'", "'")
        decoded = decoded.replace("\\", "")
        decoded = " ".join(decoded.split())
        return decoded.lower().strip()
    except:
        return text.lower().strip()
