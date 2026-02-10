@echo off
echo [SETUP] Installing MySQL Connector...
pip install mysql-connector-python

echo.
echo [INFO] Make sure XAMPP (MySQL) is running!
echo [INFO] Starting Secure Login System (MySQL Version)...
python app_mysql.py
pause
