from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
import base64
from flask import Flask, jsonify, request
import jwt
import rsakeys
import time
import json

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['JSONIFY_MIMETYPE'] = "application/json"

def int_to_base64url(n):
    data = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    #holds keys that are not expired
    keys = rsakeys.key_manager.get_unexpired_keys()
    jwks_data = {
        "keys": [
            {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": key['kid'],
                "n": int_to_base64url(serialization.load_pem_public_key(key['public'].encode()).public_numbers().n),
                "e": int_to_base64url(65537)
            }
            for key in keys
        ]
    }
    return app.response_class(response=json.dumps(jwks_data), status=200, mimetype='application/json')

@app.route("/.well-known/jwks.json", methods=["POST", "PUT", "DELETE", "PATCH"])
def jwks_method_not_allowed():
    return app.response_class(response=json.dumps({"error": "Method not allowed"}), status=405, mimetype='application/json')

#auth route, authentication and data initialization
@app.route('/auth', methods=['POST'])
def authenticate():
    print("Entered /auth route")
    data = '{"username": "userABC", "password": "password123"}'
    jdata = json.loads(data)
    username = jdata["username"]
    password = jdata["password"]
    if not data:
        print("No data received. Using default values.")
        data = {
            "username" : "user123",
            "password" : "password123"
        }
        jdata = json.dumps(data)
    else:
        try:
            json_data = json.loads(data)
            subject = json_data.get('sub', 'default')
            issuer = json_data.get('iss', 'default')
        except json.JSONDecodeError:
            print("Error decoding JSON")
            return json.dumps({"error": "Malformed JSON payload"}), 400
    #generating key
    key = rsakeys.key_manager.generate_key()
    if not key:
        return json.dumps({"error": "Authentication failed"}), 401

    headers = {
        'alg': 'RS256',
        'typ': 'JWT',
        'kid': key['kid']
    }
    payload = {
        'username' : username,
        'password' : password,
        'exp' : key['expiry']
    }


    try:
        #encoding signature of header+payload
        token = jwt.encode(payload, key['private'], algorithm='RS256', headers=headers)
        print(token)
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return json.dumps({"error": "Error generating JWT"}), 500
    print(f"Generated JWT with kid: {key['kid']}")
    return token

def check_auth(username, password):
    return username == 'userABC' and password == 'password123'

@app.route("/auth", methods=["GET", "PUT", "DELETE", "PATCH", "HEAD"])
def auth_method_not_allowed():
    return app.response_class(response=json.dumps({"error": "Method not allowed"}), status=405, mimetype='application/json')

if __name__ == "__main__":
    app.run(port=8080)
