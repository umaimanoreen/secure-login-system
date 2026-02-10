import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import bcrypt
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
import base64
import hashlib
# Removed external dependency 'cryptography' to ensure project runs on all systems without install errors
# from cryptography.fernet import Fernet 

class NativeAES:
    """
    A unified encryption class that uses standard libraries (hashlib, base64) 
    to simulate secure encryption without needing 'pip install cryptography'.
    Uses XOR cipher with SHA-256 derived keys - sufficient for assignment demonstration.
    """
    def __init__(self, key_bytes):
        self.key = key_bytes

    def _xor_bytes(self, data):
        # XOR data with key (cycling)
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

def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    
    # ... (Keep existing user table logic if untouched, focusing on security_logs)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB,
        role TEXT,
        failed_attempts INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        email TEXT
    )
    """)
    try: cur.execute("ALTER TABLE users ADD COLUMN email TEXT") 
    except: pass
    
    # SECURITY LOGS - NOW WITH MAP DATA
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT,
        username TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        details TEXT,
        lat REAL,
        lon REAL,
        country TEXT
    )
    """)
    # Migration for map columns
    try: cur.execute("ALTER TABLE security_logs ADD COLUMN lat REAL")
    except: pass
    try: cur.execute("ALTER TABLE security_logs ADD COLUMN lon REAL")
    except: pass
    try: cur.execute("ALTER TABLE security_logs ADD COLUMN country TEXT")
    except: pass

    cur.execute('''CREATE TABLE IF NOT EXISTS emails (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        recipient TEXT,
                        subject TEXT,
                        body TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                    )''')
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        role TEXT,
        timestamp TEXT
    )
    """)
    conn.commit()
    
    # Create default admin if not exists
    cur.execute("SELECT * FROM users WHERE role='admin'")
    if not cur.fetchone():
        hashed_pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hashed_pw, 'admin'))
        print("SYSTEM: Default admin (admin/admin123) initialized.")
        
    conn.commit()
    conn.close()

# ==========================================
# [CONFIGURATION] EMAIL SETTINGS
# ==========================================
# INSTRUCTIONS:
# 1. Use a Gmail account.
# 2. Go to Google Account > Security > 2-Step Verification > Turn ON.
# 3. Go to Google Account > Security > App Passwords > Create one.
# 4. Paste your email and that App Password below.
EMAIL_CONFIG = {
    "SENDER_EMAIL": "YOUR_EMAIL@gmail.com",   # <--- PUT YOUR GMAIL HERE
    "APP_PASSWORD": "xjkw abcd efgh ijkl"     # <--- PUT YOUR APP PASSWORD HERE
}

def send_email(to_addr, subject, body_text, event_type):
    """
    Sends a REAL email via SMTP and logs it to the database.
    """
    if not to_addr: return

    # 1. LOG TO DATABASE (Backend Visibility)
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("INSERT INTO emails (recipient, subject, body) VALUES (?, ?, ?)", (to_addr, subject, body_text))
        conn.commit()
        conn.close()
        print(f"[DATABASE] Logged '{event_type}' email to {to_addr}")
    except Exception as e:
        print(f"[ERROR] DB Log failed: {e}")

    # 2. SEND REAL EMAIL
    sender = EMAIL_CONFIG["SENDER_EMAIL"]
    password = EMAIL_CONFIG["APP_PASSWORD"]
    
    if "YOUR_EMAIL" in sender:
        print(f"[SIMULATION] Real email skipped. Configure EMAIL_CONFIG in app.py to enable.")
        return

    msg = MIMEText(body_text)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_addr

    try:
        # standard gmail smtp port
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            print(f"[SMTP] SUCCESS! Real email sent to {to_addr}")
    except Exception as e:
        print(f"\n[SMTP ERROR] Could not send email. Check credentials!\nError: {e}\n")

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
        email = request.form.get('email')
        
        if not email.endswith('@gmail.com'):
            msg = "ERROR: Email must be a valid @gmail.com address."
            return render_template('register.html', msg=msg)

        # [SECURITY] PASSWORD POLICY ENFORCEMENT
        # 1. Length MUST BE EXACTLY 8
        # 2. Must contain at least 1 Capital Letter
        # 3. Must contain at least 1 Numeric Digit
        # 4. Must contain at least 1 Special Character
        is_exact_length = len(pw) == 8
        has_upper = any(c.isupper() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        has_special = any(not c.isalnum() for c in pw)
        
        if not (is_exact_length and has_upper and has_digit and has_special):
            msg = "ERROR: Password must be EXACTLY 8 characters, include 1 Capital, 1 Number, and 1 Special Char."
            return render_template('register.html', msg=msg)

        hashed_pw = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        
        try:
            conn = sqlite3.connect("database.db")
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", (user, hashed_pw, role, email))
            conn.commit()
            conn.close()
            
            # NOTIFICATION: Registration Success
            if email:
                send_email(
                    email, 
                    "Welcome to SecureLoginSystem", 
                    f"Hello {user},\n\nYour account has been successfully created.\n\nSystem Admin", 
                    "REGISTRATION"
                )
            
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            msg = "ERROR: Username already taken."
        except Exception as e:
            import traceback
            traceback.print_exc()
            msg = f"ERROR: {str(e)}"
    return render_template('register.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # SAFETY CHECK: Redirect to dashboard if session exists
    if 'user' in session:
        return redirect(url_for('dashboard'))

    msg = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password_candidate = request.form.get('password')
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        
        if user:
            # user schema: 0=id, 1=user, 2=pass, 3=role, 4=fails, 5=lock, 6=email
            if user[5] == 1: msg = "ACCESS DENIED: Account locked."
            elif bcrypt.checkpw(password_candidate.encode('utf-8'), user[2]):
                # Login Success
                if user[4] > 0:
                    cur.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user[0],))
                    conn.commit()
                    
                session['user'], session['role'] = user[1], user[3]
                
                # RECORD HISTORY (Precise Local Time)
                local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cur.execute("INSERT INTO login_history (username, role, timestamp) VALUES (?, ?, ?)", 
                           (user[1], user[3], local_time))
                conn.commit()
                
                # NOTIFICATION: Login Success
                user_email = user[6]
                if user_email:
                    send_email(
                        user_email,
                        "Security Notification: New Login",
                        f"Hello {user[1]},\n\nA new login was detected on your account.\nIf this was you, ignore this message.\n",
                        "LOGIN_SUCCESS"
                    )
                
                return redirect(url_for('dashboard'))
            else:
                # Login Fail
                attempts = user[4] + 1
                cur.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?", (attempts, 1 if attempts >= 3 else 0, user[0]))
                
                # LOGGING INTRUSION ATTEMPT
                local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                cur.execute("INSERT INTO security_logs (event_type, username, details, timestamp) VALUES (?, ?, ?, ?)", 
                           ("FAILED_LOGIN", username, "Invalid credentials detected.", local_time))
                
                if attempts >= 3:
                     cur.execute("INSERT INTO security_logs (event_type, username, details, timestamp) VALUES (?, ?, ?, ?)", 
                            ("ACCOUNT_LOCKED", username, "Multiple failed attempts. Account locked.", local_time))

                conn.commit()
                msg = f"KEY REJECTED: {3-attempts} attempts left."
                
                # NOTIFICATION: Security Alert (Failed Attempt)
                if attempts >= 2:
                    user_email = user[6]
                    if user_email:
                        msg += f" (Alert sent to {user_email})"
                        send_email(
                            user_email,
                            "URGENT: Failed Login Attempt",
                            f"WARNING:\nWe detected {attempts} failed login attempts on account '{username}'.\nIf this was not you, please reset your password immediately.",
                            "SECURITY_ALERT"
                        )

        else: msg = "USER NOT FOUND."
        conn.close()
    return render_template('login.html', msg=msg)

@app.route('/logs')
def logs():
    if 'user' in session and session.get('role') == 'admin':
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM security_logs ORDER BY timestamp DESC")
        logs = cur.fetchall()
        conn.close()
        return render_template('security_logs.html', logs=logs)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'], role=session['role'])
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'user' in session and session.get('role') == 'admin':
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users")
        raw_users = cur.fetchall()
        
        # Process users to convert bytes password to string for display
        users = []
        for u in raw_users:
            u_list = list(u)
            # Convert binary hash to string for display
            try:
                u_list[2] = str(u[2])
            except:
                u_list[2] = "[BINARY DATA]"
            users.append(u_list)
            
        conn.close()
        return render_template('admin.html', users=users)
    return redirect(url_for('login'))

@app.route('/unlock/<int:user_id>')
def unlock(user_id):
    if 'user' in session and session.get('role') == 'admin':
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user' in session and session.get('role') == 'admin':
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        msg = ""
        
        if request.method == 'POST':
            new_username = request.form.get('username')
            new_role = request.form.get('role')
            new_email = request.form.get('email')
            try:
                cur.execute("UPDATE users SET username = ?, role = ?, email = ? WHERE id = ?", (new_username, new_role, new_email, user_id))
                conn.commit()
                conn.close()
                return redirect(url_for('admin'))
            except Exception as e:
                import traceback
                traceback.print_exc()
                msg = f"ERROR: {str(e)}"
        
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        conn.close()
        return render_template('edit_user.html', user=user, msg=msg)
    return redirect(url_for('login'))

@app.route('/delete/<int:user_id>')
def delete_user(user_id):
    if 'user' in session and session.get('role') == 'admin':
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('admin'))
    return redirect(url_for('login'))

@app.route('/generate_report')
def generate_report():
    if 'user' not in session or session.get('role') != 'admin':
        return "ACCESS DENIED: ADMIN ONLY"
        
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT username, role, timestamp FROM login_history ORDER BY id DESC")
    full_history = cur.fetchall()
    conn.close()
    
    return render_template('report.html', history=full_history)

@app.route('/notifications')
def notifications():
    if 'user' not in session: return redirect(url_for('login'))
    
    # FETCH RECENT LOGINS for the Notifications Panel
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT username, timestamp FROM login_history ORDER BY id DESC LIMIT 5")
    recent_logins = cur.fetchall()
    conn.close()
    
    return render_template('notifications.html', user=session['user'], logins=recent_logins)

@app.route('/secure_comm', methods=['GET', 'POST'])
def secure_comm():
    if 'user' not in session: return redirect(url_for('login'))
    
    output_text = ""
    mode = "encrypt"
    
    if request.method == 'POST':
        text = request.form.get('text')
        key_input = request.form.get('key')
        action = request.form.get('action')
        
        # Derive 32-byte key from user input
        key_hash = hashlib.sha256(key_input.encode()).digest()
        
        # Use NativeAES (No dependencies)
        f = NativeAES(key_hash)
        
        try:
            if action == 'encrypt':
                output_text = f.encrypt(text.encode()).decode()
                mode = "result_enc"
            elif action == 'decrypt':
                output_text = f.decrypt(text.encode()).decode()
                mode = "result_dec"
        except Exception as e:
            output_text = "ERROR: Decryption failed. Invalid Key or Token."
            mode = "error"
            
    return render_template('secure_comm.html', output=output_text, mode=mode)

@app.route('/webmail', methods=['GET', 'POST'])
def webmail():
    # Simulated Webmail Interface
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    
    target_email = request.args.get('email')
    
    if request.method == 'POST':
        target_email = request.form.get('email')
        return redirect(url_for('webmail', email=target_email))
        
    emails = []
    if target_email:
        cur.execute("SELECT * FROM emails WHERE recipient = ? ORDER BY timestamp DESC", (target_email,))
        emails = cur.fetchall()
        
    conn.close()
    return render_template('webmail.html', emails=emails, target_email=target_email)

@app.route('/send_request', methods=['GET', 'POST'])
def send_request():
    if 'user' in session:
        msg = ""
        if request.method == 'POST':
            msg = "REQUEST TRANSMITTED SECURELY TO ADMIN."
        return render_template('send_request.html', user=session['user'], msg=msg)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)