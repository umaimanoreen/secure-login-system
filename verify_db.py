import sqlite3

def verify_emails():
    print("\n--- [DATABASE VERIFICATION] EMAIL LOGS ---")
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        
        # Check if table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'")
        if not cur.fetchone():
            print("Table 'emails' does not exist yet.")
            return

        cur.execute("SELECT * FROM emails ORDER BY timestamp DESC")
        rows = cur.fetchall()
        
        print(f"{'ID':<5} | {'RECIPIENT':<25} | {'SUBJECT':<30} | {'TIMESTAMP'}")
        print("-" * 90)
        
        for r in rows:
            # r = (id, recipient, subject, body, timestamp)
            # Truncate subject if too long
            subj = (r[2][:27] + '..') if len(r[2]) > 27 else r[2]
            print(f"{r[0]:<5} | {r[1]:<25} | {subj:<30} | {r[4]}")
            
        print("-" * 90)
        print(f"Total Records: {len(rows)}")
        conn.close()
        
    except Exception as e:
        print(f"Error reading database: {e}")

if __name__ == "__main__":
    verify_emails()
