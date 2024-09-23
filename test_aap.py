import pytest
from aap import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Test the /.well-known/jwks.json endpoint
def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert "keys" in data

# Test the /auth endpoint for a valid JWT
def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data

# Test the /auth?expired=true endpoint for an expired JWT
def test_auth_expired(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data

