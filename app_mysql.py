import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
import base64
import hashlib

# NATIVE ENCRYPTION CLASS (Same as before)
class NativeAES:
    def __init__(self, key_bytes):
        self.key = key_bytes
    def _xor_bytes(self, data):
        return bytes([b ^ self.key[i % len(self.key)] for i, b in enumerate(data)])
    def encrypt(self, message_bytes):
        xored = self._xor_bytes(message_bytes)
        return base64.urlsafe_b64encode(xored)
    def decrypt(self, token_bytes):
        try:
            xored = base64.urlsafe_b64decode(token_bytes)
            return self._xor_bytes(xored)
        except:
            raise Exception("Invalid Token")

app = Flask(__name__)
app.secret_key = "cyber_security_mainframe_key"

# DATABASE CONFIGURATION
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # XAMPP default
    'database': 'secure_login'
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        # Fallback for initial setup if DB doesn't exist
        if err.errno == 1049: # Unknown database
             conn = mysql.connector.connect(host='localhost', user='root', password='')
             cur = conn.cursor()
             cur.execute("CREATE DATABASE IF NOT EXISTS secure_login")
             conn.close()
             return mysql.connector.connect(**DB_CONFIG)
        raise err

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. USERS TABLE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        password BLOB,
        role VARCHAR(50),
        failed_attempts INT DEFAULT 0,
        is_locked INT DEFAULT 0,
        email VARCHAR(255)
    )
    """)
    
    # 2. SECURITY LOGS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(50),
        username VARCHAR(255),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )
    """)
    
    # 3. EMAILS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS emails (
        id INT AUTO_INCREMENT PRIMARY KEY,
        recipient VARCHAR(255),
        subject VARCHAR(255),
        body TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 4. LOGIN HISTORY
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        role VARCHAR(50),
        timestamp VARCHAR(255)
    )
    """)
    
    # Create Default Admin
    cur.execute("SELECT * FROM users WHERE role='admin'")
    if not cur.fetchone():
        hashed_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", ('admin', hashed_pw, 'admin'))
        print("SYSTEM: Default admin (admin/admin123) initialized in MySQL.")

    conn.commit()
    conn.close()

# EMAIL CONFIG (SAME AS BEFORE)
EMAIL_CONFIG = {
    "SENDER_EMAIL": "YOUR_EMAIL@gmail.com", 
    "APP_PASSWORD": "xjkw abcd efgh ijkl"
}

def send_email(to_addr, subject, body_text, event_type):
    if not to_addr: return
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO emails (recipient, subject, body) VALUES (%s, %s, %s)", (to_addr, subject, body_text))
        conn.commit()
        conn.close()
        print(f"[MYSQL] Logged '{event_type}' email to {to_addr}")
    except Exception as e:
        print(f"[ERROR] DB Log failed: {e}")

    # Real Email Sending Logic (same)
    sender = EMAIL_CONFIG["SENDER_EMAIL"]
    if "YOUR_EMAIL" in sender:
        return
    msg = MIMEText(body_text)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_addr
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender, EMAIL_CONFIG["APP_PASSWORD"])
            server.send_message(msg)
            print(f"[SMTP] Sent to {to_addr}")
    except Exception as e:
        print(f"[SMTP ERROR] {e}")

# ROUTES

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        role = request.form.get('role', 'user')
        email_addr = request.form.get('email')

        # VALIDATION RULES
        if not email_addr.endswith('@gmail.com'):
            return render_template('register.html', msg="ERROR: Email must be @gmail.com")
        
        if not (len(pw) == 8 and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
             return render_template('register.html', msg="ERROR: Password must be EXACTLY 8 chars, 1 Capital, 1 Number, 1 Special.")

        hashed_pw = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password, role, email) VALUES (%s, %s, %s, %s)", (user, hashed_pw, role, email_addr))
            conn.commit()
            conn.close()
            
            if email_addr:
                send_email(email_addr, "Welcome", f"Hello {user}, Account Created.", "REGISTRATION")
                
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            if err.errno == 1062: # Duplicate entry
                msg = "ERROR: Username already taken."
            else:
                msg = f"ERROR: {err}"
    return render_template('register.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session: return redirect(url_for('dashboard'))
    msg = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password_candidate = request.form.get('password')
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user:
            # MySQL returns tuple. Indices depend on schema order: 
            # id(0), username(1), password(2), role(3), failed(4), locked(5), email(6)
            if user[5] == 1: msg = "ACCESS DENIED: Account locked."
            elif bcrypt.checkpw(password_candidate.encode('utf-8'), user[2]): # user[2] is binary blob
                # SUCCESS
                if user[4] > 0:
                    cur.execute("UPDATE users SET failed_attempts = 0 WHERE id = %s", (user[0],))
                    conn.commit()
                
                session['user'], session['role'] = user[1], user[3]
                
                local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("INSERT INTO login_history (username, role, timestamp) VALUES (%s, %s, %s)", (user[1], user[3], local_time))
                conn.commit()
                
                if user[6]:
                    send_email(user[6], "New Login", f"Hello {user[1]}, login detected.", "LOGIN_SUCCESS")
                
                return redirect(url_for('dashboard'))
            else:
                # FAIL
                attempts = user[4] + 1
                cur.execute("UPDATE users SET failed_attempts = %s, is_locked = %s WHERE id = %s", (attempts, 1 if attempts >= 3 else 0, user[0]))
                
                local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("INSERT INTO security_logs (event_type, username, details, timestamp) VALUES (%s, %s, %s, %s)", 
                           ("FAILED_LOGIN", username, "Invalid credentials.", local_time))
                
                if attempts >= 3:
                     cur.execute("INSERT INTO security_logs (event_type, username, details, timestamp) VALUES (%s, %s, %s, %s)", 
                            ("ACCOUNT_LOCKED", username, "Locked due to failed attempts.", local_time))
                
                conn.commit()
                msg = f"KEY REJECTED: {3-attempts} attempts left."
                
        else: msg = "USER NOT FOUND."
        conn.close()
    return render_template('login.html', msg=msg)

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/notifications')
def notifications():
    if 'user' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, timestamp FROM login_history ORDER BY id DESC LIMIT 5")
    recent_logins = cur.fetchall()
    conn.close()
    return render_template('notifications.html', user=session['user'], logins=recent_logins)

@app.route('/generate_report')
def generate_report():
    if 'user' not in session or session.get('role') != 'admin':
         return "ACCESS DENIED"
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT username, role, timestamp FROM login_history ORDER BY id DESC")
    full_history = cur.fetchall()
    conn.close()
    return render_template('report.html', history=full_history)

@app.route('/admin')
def admin():
    if 'user' in session and session.get('role') == 'admin':
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users")
        raw_users = cur.fetchall()
        users = []
        for u in raw_users:
            u_list = list(u)
            try: u_list[2] = str(u[2])
            except: u_list[2] = "[BINARY DATA]"
            users.append(u_list)
        conn.close()
        return render_template('admin.html', users=users)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    try:
        init_db()
        app.run(debug=True)
    except Exception as e:
        print("ERROR: Could not connect to MySQL. Is XAMPP running?")
        print(f"Details: {e}")
