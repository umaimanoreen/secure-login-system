import sqlite3

def show_users():
    print("\n--- [DATABASE CONTENT] USERS TABLE ---")
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        
        cur.execute("SELECT id, username, password, role, email FROM users")
        rows = cur.fetchall()
        
        print(f"{'ID':<5} | {'USERNAME':<15} | {'ROLE':<10} | {'EMAIL':<25} | {'PASSWORD HASH (truncated)'}")
        print("-" * 100)
        
        for r in rows:
            # r = (id, username, password, role, email)
            # Truncate hash for readability
            pw_display = str(r[2])[:30] + "..." 
            print(f"{r[0]:<5} | {r[1]:<15} | {r[3]:<10} | {str(r[4]):<25} | {pw_display}")
            
        print("-" * 100)
        print(f"Total Users: {len(rows)}")
        conn.close()
        
    except Exception as e:
        print(f"Error reading database: {e}")

if __name__ == "__main__":
    show_users()
