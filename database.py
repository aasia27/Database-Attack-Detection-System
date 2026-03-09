import oracledb

DSN = "127.0.0.1:1522/xepdb1"
USER = "system"
PASSWORD = "system"

def get_connection():
    return oracledb.connect(user=USER, password=PASSWORD, dsn=DSN)

def log_attack(username: str, input_text: str, attack_type: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO attack_logs (username, input_text, attack_type)
        VALUES (:1, :2, :3)
        """,
        [username, input_text, attack_type]
    )
    conn.commit()
    cur.close()
    conn.close()

def validate_login(username: str, password: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM users WHERE username = :1 AND password = :2",
        [username, password]
    )
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    return count == 1

def get_recent_attacks(limit: int = 10):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT username, attack_type, TO_CHAR(log_time, 'YYYY-MM-DD HH24:MI:SS')
        FROM attack_logs
        ORDER BY log_time DESC
        FETCH FIRST {limit} ROWS ONLY
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows