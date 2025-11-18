import os
import time
from utils.normalize import normalize
import re
from config.settings import settings

LOG_PATH = settings.ACCESS_LOG_PATH

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

def detect(line):
    text = normalize(line)
    
    for p in PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True, p, "SQL Injection"

    return False, None, None