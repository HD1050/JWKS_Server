from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from passlib.context import CryptContext
import os
import base64
import uuid
import sqlite3


app = Flask(__name__)

# Store keys in a dict
keys = {}

# Encryption Key
aes_key = bytes.fromhex(os.environ.get('NOT_MY_KEY'))

# Create a password context instance
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()


# Initialize the database to include the users table
def init_db_with_users():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Call the function to ensure the users table exists
init_db_with_users()

# Your encryption function might look something like this:
def encrypt_private_key(private_key_pem, aes_key):
    # AES-GCM requires a nonce, never reuse a nonce with the same key
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_key = aesgcm.encrypt(nonce, private_key_pem, None)
    return nonce + encrypted_key  # Prepend nonce to the encrypted key


def create_key_pair_and_save_to_db(expiry_duration=3600):  # Expiry duration in seconds
    # Generate the RSA key pair using your existing function
    private_key, public_key = generate_rsa_key()
    
    # Serialize the private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the serialized private key using your encrypt_private_key function
    encrypted_private_key = encrypt_private_key(pem, aes_key)

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

    # Fetch the user ID based on the username
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    user_id = user[0] if user else None
    
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
    
    return None, None, user_id

def authenticate_user(username, password):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    # Verify the password using pwd_context
    if user and pwd_context.verify(password, user[1]):
        return True, user[0]  # User is authenticated, return True and user_id
    else:
        return False, None  # User is not authenticated, return False and None

        
def log_auth_attempt(ip, user_id):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO auth_logs(request_ip, user_id, request_timestamp) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (ip, user_id))
    conn.commit()
    conn.close()


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
    # Extract credentials from the request
    credentials = request.get_json()
    username = credentials.get('username')
    password = credentials.get('password')

    # Authenticate user
    user_authenticated, user_id = authenticate_user(username, password)

    # Log the authentication attempt
    ip_address = request.remote_addr
    log_auth_attempt(ip_address, user_id if user_authenticated else None)

    if user_authenticated:
        # Retrieve the private key and kid from the database
        private_key, kid = get_private_key_from_db(expired=False)
        if not private_key:
            return jsonify({"error": "Server error"}), 500

        # Issue a JWT token
        exp = datetime.utcnow() + timedelta(minutes=10)  # Token expiry set to 10 minutes
        payload = {
            'sub': str(user_id),  # Subject should be the user ID
            'name': username,     # This could be the user's name or other identifying information
            'iat': int(datetime.utcnow().timestamp()),  # Issued at time
            'exp': int(exp.timestamp()),               # Expiration time
        }

        token = jwt.encode(
            payload,
            private_key,
            algorithm='RS256',
            headers={'kid': kid}
        )

        return jsonify({'token': token}), 200
    else:
        # Authentication failed
        return jsonify({"error": "Invalid credentials"}), 401





@app.route('/register', methods=['POST'])
def register():
    # Extract the data from the request
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({'error': 'Missing username or email'}), 400

    # Generate a UUID4 password and hash it with argon2
    password = str(uuid.uuid4())
    hashed_password = pwd_context.hash(password)

    try:
        # Connect to the database
        conn = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = conn.cursor()

        # Create the user record
        cursor.execute('''
            INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)
        ''', (data['username'], hashed_password, data['email']))

        # Commit and close the database connection
        conn.commit()
        conn.close()

        # Return the generated password to the user
        return jsonify({'password': password}), 201  # 201 Created
    except sqlite3.IntegrityError:
        # This exception is thrown when the username or email already exists
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        # For any other exceptions, return a 500 error
        return jsonify({'error': str(e)}), 500




if __name__ == '__main__':

    init_db() #initialize the database
    init_db_with_users()  # Initialize the users table
     # Generate a key pair on startup running Flask
    create_key_pair_and_save_to_db(expiry_duration=-3600) #create key and save to db
    create_key_pair_and_save_to_db(expiry_duration=3600)
    app.run(port=8080, debug=True)