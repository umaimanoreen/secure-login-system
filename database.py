import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()

cur.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password BLOB,
    role TEXT,
    failed_attempts INTEGER DEFAULT 0,
    is_locked INTEGER DEFAULT 0
)
""")

conn.commit()
conn.close()
print("Database created successfully")
