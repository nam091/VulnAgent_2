import sqlite3
import subprocess

from flask import Flask, render_template_string, request

app = Flask(__name__)

# Vulnerable database connection
def get_db():
    return sqlite3.connect('database.db')

@app.route('/user/<username>')
def user_profile(username):
    # SQL Injection vulnerability
    db = get_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    user = cursor.fetchone()
    
    # XSS vulnerability
    template = f'''
    <h1>Welcome {username}!</h1>
    <div>Your profile data: {user}</div>
    '''
    return render_template_string(template)

@app.route('/download')
def download_file():
    # Path traversal vulnerability
    filename = request.args.get('filename')
    return open(filename, 'r').read()

@app.route('/ping')
def ping_host():
    # Command injection vulnerability
    host = request.args.get('host', 'localhost')
    # Dangerous - allows command injection
    result = subprocess.check_output(f'ping -c 1 {host}', shell=True)
    return result.decode()

@app.route('/login', methods=['POST'])
def login():
    # Hardcoded credentials vulnerability
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == 'admin' and password == 'admin123':
        return 'Login successful!'
    return 'Login failed!'

if __name__ == '__main__':
    # Security misconfiguration - debug mode enabled
    app.run(host='0.0.0.0', port=9000)
