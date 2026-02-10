# Secure Login System

A secure, robust authentication system built with Python (Flask) and SQLite.

## Features
- **Secure Authentication**: User registration and login with bcrypt password hashing.
- **Role-Based Access Control**: Admin and User roles with separate dashboards.
- **Account Locking**: Automatically locks accounts after 3 failed login attempts.
- **Security Logs**: Tracks failed login attempts and potential intrusions (with location simulation).
- **Email Notifications**: specific alerts for logins and security breaches.
- **Secure Communication**: Built-in tool for message encryption/decryption.

## How to Run

1.  **Install Python**: Ensure you have Python installed on your system.
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the Application**:
    ```bash
    python app.py
    ```
4.  **Access the Website**:
    Open your browser and go to: `http://127.0.0.1:5000`

## Default Admin Credentials
- **Username**: `admin`
- **Password**: `admin123`

## Project Structure
- `app.py`: Main application logic.
- `database.db`: SQLite database (auto-generated).
- `templates/`: HTML files for the user interface.
- `static/`: CSS and assets.

---
*Created for Cyber Security Assignment*
