
import os
import time
from urllib.parse import unquote
import re

LOG_PATH = os.environ.get(
    "LOG_PATH",
    r"C:\Users\Pc\Documents\Organigramme-Info\Web-Dev-Backend\access.log"
)

PATTERNS = [
    # Basic SQLi
    r"or\s*1\s*=\s*1",
    r"or\s*'.*'.*=.*'.*'",
    r"or\s+true",
    r"or\s+false",
    
    # SELECT patterns
    r"select\s+\*?\s+from",
    r"select.*from.*where",
    r"select.*as",
    
    # UNION attacks
    r"union\s+select",
    r"union\s+all\s+select",
    r"union.*from",
    
    # DROP/DELETE
    r"drop\s+table",
    r"drop\s+database",
    r";\s*drop",
    r"delete\s+from",
    
    # INSERT/UPDATE
    r"insert\s+into",
    r"update\s+.*set",
    
    # Time-based
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"waitfor\s+delay",
    
    # System commands
    r"xp_cmdshell",
    r"exec\s+xp",
    r"execute\s+xp",
    
    # Comments
    r"--\s",
    r"#\s*$",
    r"/\*",
    r"\*/",
    
    # Stacked queries
    r";\s*select",
    r";\s*insert",
    r";\s*update",
    r";\s*delete",
    r";\s*exec",
    
    # Load file
    r"load_file\s*\(",
    r"into\s+outfile",
    r"into\s+dumpfile",
    
    # Boolean
    r"and\s+1\s*=\s*1",
    r"and\s+1\s*=\s*2",
    
    # Order by
    r"order\s+by",
    r"group\s+by",
    
    # Information schema
    r"information_schema",
    r"mysql\.user",
    r"sysobjects",
    
    # Hex encoding
    r"0x[0-9a-f]{2,}",
    
    # CASE/WHEN
    r"case\s+when",
    
    # Stored procedures
    r"exec\s*\(",
    r"execute\s*\(",
]

def normalize(s: str) -> str:
    if not s:
        return ""
    try:
        decoded = unquote(s)
        decoded = decoded.replace('\\"', '"').replace("\\'", "'").replace('\\', '')
        return decoded.lower().strip()
    except:
        return str(s).lower().strip()

def check_line(line):
    normalized = normalize(line)
    for pattern in PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE): 
            return True, pattern
        
    return False, None

def main():
    print("Python Watcher has started - monitoring access.log...")
    print("=" * 60)
    
    last_position = 0
    while True:
        try:
            if not os.path.exists(LOG_PATH):
                time.sleep(1)
                continue
            
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()
            
            for line in new_lines:
                is_sqli, pattern = check_line(line)
                
                if is_sqli:
                    print(f"-ALERT- SQL Injection detected !")
                    print(f" Pattern: {pattern}")
                    print(f" Line: {line.strip()}")
                    print("-" * 60)
                    
                    with open("alerts.log", "a", encoding="utf-8") as f:
                        f.write(f"SQLI DETECTED - Pattern: {pattern} - {line.strip()}\n")
            
            time.sleep(0.5)
        
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
