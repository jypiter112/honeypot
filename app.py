from flask import Flask, render_template, request, Response
import logging
import json
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

app = Flask(__name__)

def load_blacklist():
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def is_blacklisted(ip):
    return ip in load_blacklist()

def save_client_info(client_info):
    # Create directory for this IP if it doesn't exist
    ip_dir = os.path.join('logs', client_info['ip'])
    if not os.path.exists(ip_dir):
        os.makedirs(ip_dir)
    
    # Save the client info
    file_path = os.path.join(ip_dir, 'client_info.json')
    with open(file_path, 'a') as f:
        json.dump(client_info, f)
        f.write('\n')

def log_client_info():
    client_info = {
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Log the information
    logging.info(f"Client IP: {client_info['ip']}")
    logging.info(f"User Agent: {client_info['user_agent']}")
    logging.info(f"Request Method: {client_info['method']}")
    logging.info(f"Request Path: {client_info['path']}")
    logging.info("-" * 50)
    
    return client_info

@app.before_request
def check_blacklist():
    client_ip = request.remote_addr
    if is_blacklisted(client_ip):
        logging.warning(f"Blacklisted IP {client_ip} attempted to access the server")
        return Response(
            "Access Denied: Your IP has been blacklisted due to suspicious activity.",
            status=401,
            mimetype='text/plain'
        )

@app.route('/')
def index():
    client_info = log_client_info()
    save_client_info(client_info)
    return render_template('index.html')

@app.before_request
def before_request():
    save_client_info(log_client_info())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 