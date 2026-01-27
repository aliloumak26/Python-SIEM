import re
from utils.normalize import normalize

# --- ENDPOINTS typiques d’upload ---
Upload_Endpoints = [
    r"/upload",
    r"/file/upload",
    r"/media/upload",
    r"/api/upload",
    r"/admin/upload",
    r"/upload.php",
]

# --- Extensions dangereuses ---
Forbidden_ext = [
    r"\.php$", r"\.php\d$", r"\.phtml$", r"\.phar$", r"\.inc$", 
    r"\.jsp$", r"\.asp$", r"\.aspx$",
    r"\.exe$", r"\.sh$", r"\.pl$", r"\.py$", r"\.cgi$",
    r"\.dll$", r"\.bat$", r"\.cmd$", 
    r"\.jar$", r"\.war$",   
]

# --- Double extensions---
Double_ext = [
    r"\.php\.", r"\.php\d\.", r"\.phtml\.", r"\.jsp\.",
    r"\.asp\.", r"\.exe\.", r"\.sh\."
]

# --- Base64 (upload via API) ---
Base64_re = re.compile(r"base64,[A-Za-z0-9+/=]{200,}")

# --- Extraction du filename dans multipart upload ---
Filename_re = re.compile(r'filename="([^"]+)"', re.IGNORECASE)


def detect(line: str):

    text = normalize(line)
    matches = []
    
    for e in Upload_Endpoints:
        if re.search(e, text, re.IGNORECASE):
            matches.append(f"upload_endpoint:{e}")

    filename = None
    m = Filename_re.search(text)
    if m:
        filename = m.group(1).lower()

        for fe in Forbidden_ext:
            if re.search(fe, filename):
                matches.append(f"forbidden_extension:{filename}")

        for de in Double_ext:
            if re.search(de, filename):
                matches.append(f"double_extension:{filename}")

        if re.search(r"%00|\\x00|\x00", filename):
            matches.append("null_byte_in_filename")

    if Base64_re.search(text):
        matches.append("base64_payload_detected")

    if filename:
        ct_match = re.search(r"content-type:\s*([^\s;]+)", text, re.IGNORECASE)
        if ct_match:
            ct = ct_match.group(1).lower()

            if ct.startswith("image/") and re.search(r"\.php|\.jsp|\.exe|\.sh", filename):
                matches.append("content_type_mismatch")

    cl_match = re.search(r"content-length:\s*(\d+)", text, re.IGNORECASE)
    if cl_match:
        try:
            size = int(cl_match.group(1))
            if size > 50 * 1024 * 1024:  # > 50MB
                matches.append(f"large_upload:{size}bytes")
        except:
            pass

    if matches:
        return True, matches, "FILE_UPLOAD"

    return False, None, None
