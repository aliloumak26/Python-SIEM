from urllib.parse import unquote

def normalize(text: str) -> str:
    if not text:
        return ""
    try:
        decoded = unquote(text)
        decoded = decoded.replace('\\"', '"').replace("\\'", "'")
        decoded = decoded.replace("\\", "")
        return decoded.lower().strip()
    except:
        return text.lower().strip()
