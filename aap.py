from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import datetime

app = Flask(__name__)

# Store RSA keys and expiry
keys = {}

def generate_rsa_key():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    # Convert to PEM format (Public and Private)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# Generate an RSA keypair and store it with expiration time and kid
def store_key():
    kid = str(len(keys) + 1)
    private_key, public_key = generate_rsa_key()
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10)  # Keys expire after 10 mins
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }
    print(f"Generated new key with kid: {kid}, expiry: {expiry}")
    return kid

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_endpoint():
    jwks = {
        "keys": []
    }
    for kid, key_data in keys.items():
        public_key = key_data['public_key']
        public_numbers = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        ).public_numbers()

        jwk = {
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": jwt.utils.base64url_encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8'),
            "e": jwt.utils.base64url_encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
        }

        # Include expired flag
        if key_data['expiry'] < datetime.datetime.now(datetime.timezone.utc):
            jwk['expired'] = True
        jwks['keys'].append(jwk)

    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def auth_endpoint():
    expired = request.args.get('expired', 'false').lower() == 'true'
    kid = list(keys.keys())[0]  # Use the first key in the dictionary

    if expired:
        key_data = keys.get(kid)
        expiry_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)  # expired time
        print(f"Issuing expired token for kid: {kid}")
    else:
        key_data = keys.get(kid)
        expiry_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)  # valid time
        print(f"Issuing valid token for kid: {kid}")

    private_key = key_data['private_key']
    
    # Adding kid to the JWT header
    token = jwt.encode(
        {"exp": expiry_time, "kid": kid},  # Payload with kid in claims
        private_key,
        algorithm="RS256",
        headers={"kid": kid}  # Make sure kid is in the JWT header
    )
    
    return jsonify({"token": token})

# Automatically generate a key at the start
store_key()

if __name__ == '__main__':
    app.run(port=8080)