# JWKS Server Implementation

A RESTful JWKS (JSON Web Key Set) server that provides public keys for verifying JWTs (JSON Web Tokens), implements key expiry, and includes authentication endpoints.

## Features

- RSA key pair generation with unique identifiers (kid)
- Key expiration management
- JWKS endpoint serving valid public keys
- Authentication endpoint for JWT issuance
- Support for expired key testing

## Prerequisites

- Python 3.12.6 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone [your-repository-url]
cd [repository-name]
```

2. Create a virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Server

1. Start the server:
```bash
python app.py
```
The server will run on `http://localhost:8080`

2. Available endpoints:
- `GET /.well-known/jwks.json`: Retrieve valid public keys in JWKS format
- `POST /auth`: Get a valid JWT
- `POST /auth?expired=true`: Get a JWT signed with an expired key

## Testing

1. Run tests with coverage:
```bash
pytest --cov=app test_app.py
```

2. Current test coverage: 97%

## Project Structure

```
jwks_server/
├── app.py              # Main server implementation
├── test_app.py         # Test suite
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## API Endpoints

### GET /.well-known/jwks.json
Returns a JWKS containing all valid (non-expired) public keys.

Example response:
```json
{
    "keys": [
        {
            "kid": "2",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "...",
            "e": "AQAB"
        }
    ]
}
```

### POST /auth
Issues a JWT signed with a valid key.

Example response:
```json
{
    "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
}
```

### POST /auth?expired=true
Issues a JWT signed with an expired key.

## Dependencies

- Flask==2.2.5
- werkzeug==2.2.3
- pyjwt[crypto]==2.8.0
- cryptography==41.0.1
- pytest==7.4.0
- pytest-cov==4.1.0

## Test Results

- Gradebot Score: 65/65
- Test Coverage: 97%
- All endpoints functioning as expected

## Author

Bibekananda Pandey
