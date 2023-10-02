import unittest
import webserver
import requests

BASE_URL = 'http://127.0.0.1:8080'
class TestServer(unittest.TestCase):

    def test_auth_endpoint(self):
        response = requests.post(f"{BASE_URL}/auth", json={"username": "userABC", "password": "password123"})
        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint(self):
        response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
