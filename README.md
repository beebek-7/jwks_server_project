# JWKS Server Project

## Overview

This project implements a basic JWKS (JSON Web Key Set) server with a RESTful API. The server generates RSA key pairs, assigns a unique Key ID (kid) and expiry timestamp to each key, and provides endpoints for serving public keys and issuing JWTs (JSON Web Tokens). The server also supports issuing expired JWTs for testing purposes based on a query parameter.

## Features

- RSA Key Generation with Key ID (kid) and expiry timestamp.
- RESTful API to serve public keys in JWKS format.
- JWT issuance through the `/auth` endpoint.
- Support for issuing expired JWTs via the `expired=true` query parameter.
- Public keys are only served if they haven't expired.

## Instructions to Run the Server

### Prerequisites

Make sure you have the following installed:
- Python 3.8 or above
- `pip` (Python package manager)
- `Flask`, `PyJWT`, and `cryptography` libraries installed. You can install these by running:
  ```bash
  pip install Flask PyJWT cryptography
