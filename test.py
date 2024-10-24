import pytest
from app import app
import json
import jwt
from cryptography.hazmat.primitives import serialization

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks_endpoint(client):
    """Test that JWKS endpoint returns valid JSON with keys"""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert isinstance(data['keys'], list)
    if len(data['keys']) > 0:
        assert 'kid' in data['keys'][0]
        assert 'n' in data['keys'][0]
        assert 'e' in data['keys'][0]

def test_auth_endpoint_valid(client):
    """Test that auth endpoint returns valid JWT"""
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    
    # Verify the JWT structure
    token = data['token']
    header = jwt.get_unverified_header(token)
    assert 'kid' in header
    
def test_auth_endpoint_expired(client):
    """Test that auth endpoint returns expired JWT when requested"""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    
    # Verify the JWT structure
    token = data['token']
    header = jwt.get_unverified_header(token)
    assert 'kid' in header

def test_jwks_no_expired_keys(client):
    """Test that JWKS endpoint doesn't return expired keys"""
    # First get an expired token to ensure we have an expired key
    auth_response = client.post('/auth?expired=true')
    auth_data = json.loads(auth_response.data)
    expired_token = auth_data['token']
    expired_kid = jwt.get_unverified_header(expired_token)['kid']
    
    # Then check JWKS endpoint
    jwks_response = client.get('/.well-known/jwks.json')
    jwks_data = json.loads(jwks_response.data)
    
    # Verify the expired key is not in the JWKS
    kids = [key['kid'] for key in jwks_data['keys']]
    assert expired_kid not in kids
