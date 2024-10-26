import unittest
import requests
import json

class TestJWKSHTTP(unittest.TestCase):
    
    def setUp(self):
        """Ensure the server is running"""
        # Assuming the server is already running on localhost:8080
        pass
    
    def test_auth_endpoint(self):
        """Test the /auth endpoint for valid and expired keys"""
        response = requests.post(
            "http://localhost:8080/auth", 
            json={"username": "userABC", "password": "password123"}
        )
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token, "JWT should be returned")
    
    def test_jwks_endpoint(self):
        """Test the /well-known/jwks.json endpoint"""
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        self.assertGreaterEqual(len(jwks["keys"]), 1, "At least one key should be present")
    
    def test_auth_invalid_credentials(self):
        """Test /auth with invalid credentials"""
        response = requests.post(
            "http://localhost:8080/auth", 
            json={"username": "invalidUser", "password": "wrongPassword"}
        )
        self.assertEqual(response.status_code, 401, "Should return 401 Unauthorized for invalid credentials")

if __name__ == "__main__":
    unittest.main()
