from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "0.0.0.0"
serverPort = 8080

def create_database():
    """Create SQLite database and keys table if they don't exist"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    
    # Create table with explicit column definitions
    sql = '''CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )'''
    c.execute(sql)
    conn.commit()
    conn.close()

def generate_and_store_keys():
    """Generate and store both valid and expired keys in the database"""
    # Generate keys
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize keys to PEM format
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiry times
    valid_exp = int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp())
    expired_exp = int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).timestamp())
    
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Insert valid key with explicit parameter binding
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    params = (valid_pem, valid_exp)
    cursor.execute(sql, params)
    
    # Insert expired key with explicit parameter binding
    sql = "INSERT INTO keys (key, exp) VALUES (?, ?)"
    params = (expired_pem, expired_exp)
    cursor.execute(sql, params)
    
    conn.commit()
    conn.close()

def get_key(expired=False):
    """Retrieve a key from the database based on expiry status"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    if expired:
        sql = "SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
        params = (current_time,)
        cursor.execute(sql, params)
    else:
        sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1"
        params = (current_time,)
        cursor.execute(sql, params)
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'kid': str(result[0]),
            'key': serialization.load_pem_private_key(result[1], password=None),
            'exp': result[2]
        }
    return None

def get_valid_keys():
    """Get all valid keys from database using parameterized query"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.datetime.now(datetime.UTC).timestamp())
    sql = "SELECT kid, key FROM keys WHERE exp > ?"
    params = (current_time,)
    cursor.execute(sql, params)
    
    valid_keys = cursor.fetchall()
    conn.close()
    return valid_keys

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        if parsed_path.path == "/auth":
            want_expired = 'expired' in params
            key_data = get_key(expired=want_expired)
            
            if not key_data:
                self.send_response(500)
                self.end_headers()
                return
            
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            if body:
                try:
                    auth_data = json.loads(body)
                    username = auth_data.get('username')
                    password = auth_data.get('password')
                    if username != "userABC" or password != "password123":
                        self.send_response(401)
                        self.end_headers()
                        return
                except json.JSONDecodeError:
                    pass
            
            headers = {
                "kid": key_data['kid']
            }
            
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.fromtimestamp(key_data['exp'], tz=datetime.UTC)
            }
            
            encoded_jwt = jwt.encode(
                token_payload, 
                key_data['key'], 
                algorithm="RS256", 
                headers=headers
            )
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            valid_keys = get_valid_keys()
            
            keys_list = []
            for kid, key_pem in valid_keys:
                private_key = serialization.load_pem_private_key(key_pem, password=None)
                numbers = private_key.private_numbers()
                
                keys_list.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            response = {"keys": keys_list}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    if not os.path.exists('totally_not_my_privateKeys.db'):
        create_database()
        generate_and_store_keys()
    
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()