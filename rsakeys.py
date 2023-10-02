from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time

class KeyManager:
    def __init__(self):
        self.keys = []
    #generating key
    def generate_key(self, expiry_duration=2, expired=False):
        # RSA private key gen
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        
        # Serialize public/private key in PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # unique key id, expiration time
        key_suffix = '-expired' if expired else ''
        key_id = f"key-{int(time.time())}{key_suffix}"
        expiry = int(time.time()) - expiry_duration

        key_data = {
            'kid': key_id,
            'private': private_pem,
            'public': public_pem,
            'expiry': expiry if not expired else int(time.time()) - 10  # making it already expired
        }
        
        if not expired:  # Only add to the keys list if it's not meant to be expired
            self.keys.append(key_data)

        return key_data


    # gets unexpired key method
    def get_unexpired_keys(self):
        current_time = int(time.time())
        return [key for key in self.keys if key['expiry'] > current_time]

    # get the key by kID
    def get_key_by_kid(self, kid):
        for key in self.keys:
            if key['kid'] == kid:
                return key
        return None

key_manager = KeyManager()
# Generate an initial key
key_manager.generate_key() 
