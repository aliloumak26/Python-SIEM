def parse_line(line):
    parts = line.strip().split(" - ")
    if len(parts) < 5:
        return None
    
    ts = parts[0].strip()
    ip = parts[1].strip()
    req = parts[2].strip()      
    status = parts[3].strip()   
    duration = parts[4].strip() 

    tokens = req.split(" ", 1)
    method = tokens[0]
    path = tokens[1] if len(tokens) > 1 else ""

    return {
        "ts": ts,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "duration": duration,
        "raw": line.strip()
    }
