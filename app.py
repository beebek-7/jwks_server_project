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
    """Generate an RSA key pair and return both private and public keys in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
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

def store_key(expired=False):
    """Store a new key pair with specified expiration status."""
    kid = str(len(keys) + 1)
    private_key, public_key = generate_rsa_key()
    
    if expired:
        # Create an already expired key (5 minutes ago)
        expiry = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    else:
        # Create a key that expires in 1 hour
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }
    print(f"Generated new key with kid: {kid}, expiry: {expiry}, expired: {expired}")
    return kid

@app.route('/')
def home():
    """Root endpoint to verify server is running."""
    return jsonify({"message": "JWKS Server is running"}), 200

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_endpoint():
    """Serve the JWKS containing only non-expired public keys."""
    jwks = {
        "keys": []
    }
    current_time = datetime.datetime.now(datetime.timezone.utc)
    
    for kid, key_data in keys.items():
        # Skip expired keys
        if key_data['expiry'] < current_time:
            continue
            
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
        jwks['keys'].append(jwk)

    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def auth_endpoint():
    """Issue a JWT signed with either a valid or expired key based on the query parameter."""
    expired = request.args.get('expired', 'false').lower() == 'true'
    current_time = datetime.datetime.now(datetime.timezone.utc)
    
    # Find appropriate key based on expired parameter
    selected_kid = None
    for kid, key_data in keys.items():
        if expired:
            if key_data['expiry'] < current_time:
                selected_kid = kid
                break
        else:
            if key_data['expiry'] > current_time:
                selected_kid = kid
                break
    
    # If no appropriate key exists, create one
    if selected_kid is None:
        selected_kid = store_key(expired=expired)
    
    key_data = keys[selected_kid]
    expiry_time = (current_time - datetime.timedelta(minutes=5) if expired 
                   else current_time + datetime.timedelta(minutes=5))
    
    # Create and sign the JWT
    token = jwt.encode(
        {
            "exp": expiry_time,
            "kid": selected_kid,
            "message": "Hello, World!"
        },
        key_data['private_key'],
        algorithm="RS256",
        headers={"kid": selected_kid}
    )
    
    return jsonify({"token": token})

# Generate initial keys (one valid, one expired) at startup
store_key(expired=True)   # Generate an expired key
store_key(expired=False)  # Generate a valid key

if __name__ == '__main__':
    print("Starting JWKS Server on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
