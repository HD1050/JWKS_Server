from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import uuid

app = Flask(__name__)

# Store keys in a dict
keys = {}

# this will create a new RSA key pair using teh cryptography **remember to download library**
def generate_rsa_key():
    private_key = rsa.generate_private_key( #this is called from the cryptography 
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
# this will create a new RSA key pair and assign it to kid
def create_key_pair(expiry_duration=3600):  # Expiry duration in seconds
    kid = str(uuid.uuid4())
    private_key, public_key = generate_rsa_key()
    expiry = datetime.utcnow() + timedelta(seconds=expiry_duration)
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }
    return kid

# For GET requests
@app.route('/.well-known/jwks.json' , methods=['GET'])
def well_known_jwks():
    return jwks()

@app.route('/jwks') #handler for HTTP GET request to /jwks URL path
def jwks():
    jwks_keys = []
    for kid, key_info in keys.items(): # Iterates over each stored key pair.
        if key_info['expiry'] > datetime.utcnow(): # Checks if the key hasn't expired.
            public_key = key_info['public_key']
            public_number = public_key.public_numbers()
            # Encodes the RSA public key components into URL-safe base64.
            e = base64.urlsafe_b64encode(public_number.e.to_bytes(3, 'big')).decode('utf-8').rstrip("=")
            n = base64.urlsafe_b64encode(public_number.n.to_bytes(256, 'big')).decode('utf-8').rstrip("=")
            jwks_keys.append({
                'kty': 'RSA',
                'kid': kid,
                'use': 'sig',
                'n': n,
                'e': e,
            })
    return jsonify({'keys': jwks_keys})

# For POST requests
@app.route('/auth', methods=['POST'])
def auth():
    expired = 'expired' in request.args
    selected_kid = None
    for kid, key_info in keys.items():
        if (not expired and key_info['expiry'] > datetime.utcnow()) or (expired and key_info['expiry'] < datetime.utcnow()):
            selected_kid = kid
            break

    if not selected_kid:
        # Generate a new key if needed, based on the 'expired' query parameter
        selected_kid = create_key_pair(-3600 if expired else 3600)

    key_info = keys[selected_kid]
    payload = {
        'sub': '1234567890',
        'name': 'John Doe',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=600 if not expired else -600),  # Adjust for expiration
    }
    # payload into JWT using selected key
    token = jwt.encode(
        payload,
        key_info['private_key'],
        algorithm='RS256',
        headers={'kid': selected_kid}
    )
    # Ensure the token is returned as expected by the gradebot tool
    return jsonify({'token': token})

if __name__ == '__main__':
    # Generate a key pair on startup running Flask
    create_key_pair()
    app.run(port=8080, debug=True)
