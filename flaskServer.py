from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import uuid
import sqlite3

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

def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()



def create_key_pair_and_save_to_db(expiry_duration=3600):  # Expiry duration in seconds
    # Generate the RSA key pair using your existing function
    private_key, public_key = generate_rsa_key()
    
    # Serialize the private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Calculate the expiry time as a Unix timestamp (integer)
    expiry_timestamp = int((datetime.utcnow() + timedelta(seconds=expiry_duration)).timestamp())

    # Save the key and the expiry timestamp into the database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    # Insert the PEM-encoded key and expiry timestamp
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiry_timestamp))
    conn.commit()
    conn.close()

    # Return the unique identifier for the key (the 'kid')
    kid = cursor.lastrowid
    return kid

def get_jwks_from_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    current_timestamp = int(datetime.utcnow().timestamp())
    
    # Select non-expired keys
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_timestamp,))
    
    jwks_keys = []
    for kid, key_pem in cursor.fetchall():
        # Load the private key from the PEM bytes
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        # Get the corresponding public key
        public_key = private_key.public_key()
        
        # Get the public numbers from the public key to create the JWK
        public_numbers = public_key.public_numbers()
        exponent = base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).decode('utf-8').rstrip('=')
        modulus = base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).decode('utf-8').rstrip('=')
        
        # Append the public key in JWKS format
        jwks_keys.append({
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),  # Ensure 'kid' is a string
            "n": modulus,
            "e": exponent,
            "alg": "RS256"
        })
    
    conn.close()
    return jwks_keys

def get_private_key_from_db(expired=False):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # We use the current UTC timestamp for comparison
    current_timestamp = int(datetime.utcnow().timestamp())

    if expired:
        # Fetch an expired key
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (current_timestamp,))
    else:
        # Fetch a non-expired key
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_timestamp,))

    row = cursor.fetchone()
    conn.close()
    
    if row:
        kid, key_pem = row
        # Convert 'kid' to a string since JWT headers expect string datatype
        kid = str(kid)
        # Deserialize the private key
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
            backend=default_backend()
        )
        return private_key, kid
    
    return None, None



# For GET requests
@app.route('/.well-known/jwks.json', methods=['GET'])
def well_known_jwks():
    jwks_keys = get_jwks_from_db() 
    return jsonify({'keys': jwks_keys})


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
    private_key, kid = get_private_key_from_db(expired=expired)

    if private_key is None:
        return jsonify({"error": "No appropriate key found."}), 404
    
    # Make sure 'kid' is a string as JWT header parameters must be strings
    kid = str(kid)

    # Determine whether to use a future or past expiration time
    expiration_offset = 600 if not expired else -600
    # Calculate the expiration time as an integer Unix timestamp
    exp = int((datetime.utcnow() + timedelta(seconds=expiration_offset)).timestamp())

    # Define the JWT payload
    payload = {
        'sub': '1234567890',  # Subject of the JWT
        'name': 'John Doe',   # Additional claim
        'iat': int(datetime.utcnow().timestamp()),  # Issued at time, also as an integer timestamp
        'exp': exp,  # Expiration time
    }

    # Encode the JWT using the private key and specifying the algorithm RS256
    token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256',
        headers={'kid': kid}  # Include the 'kid' in the JWT headers
    )

    # Return the JWT in the response, encoded as a string (pyjwt does this encoding)
    return jsonify({'token': token})




if __name__ == '__main__':
    init_db() #initialize the database
     # Generate a key pair on startup running Flask
    create_key_pair_and_save_to_db(expiry_duration=-3600) #create key and save to db
    create_key_pair_and_save_to_db(expiry_duration=3600)
    app.run(port=8080, debug=True)
