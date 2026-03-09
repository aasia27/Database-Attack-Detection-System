import re

SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+\d+=\d+",      # OR 1=1
    r"'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+'?",  # ' or '1'='1
    r"--",                               # comment
    r";",                                # query chaining
    r"/\*|\*/",                          # /* */
    r"\bunion\b\s+\bselect\b",           # UNION SELECT
    r"\bdrop\b|\btruncate\b|\balter\b",  # DROP/ALTER/TRUNCATE
]

def detect_sql_injection(text: str) -> bool:
    if not text:
        return False
    t = text.lower()
    return any(re.search(p, t) for p in SQLI_PATTERNS)

def get_attack_type(text: str) -> str:
    t = (text or "").lower()
    if "union" in t:
        return "UNION-based SQLi"
    if "drop" in t or "alter" in t or "truncate" in t:
        return "Destructive SQLi"
    if "--" in t or "/*" in t:
        return "Comment-based SQLi"
    if "or" in t and "1=1" in t:
        return "Boolean-based SQLi"
    return "SQL Injection"