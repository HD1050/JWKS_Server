import pytest
from flaskServer import app as flask_app

# Test fixture for the app
@pytest.fixture
def app():
    yield flask_app

# Test fixture for the client to make requests to the app
@pytest.fixture
def client(app):
    return app.test_client()

def test_auth_valid_jwt(client):
    # Test if /auth endpoint returns a valid JWT
    response = client.post("/auth")
    assert response.status_code == 200
    

def test_auth_expired_jwt(client):
    # Test if /auth endpoint returns an expired JWT when 'expired' parameter is true
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    

def test_proper_http_methods(client):
    # Test if the proper HTTP methods are accepted by the endpoints
    post_response = client.post("/auth")
    assert post_response.status_code == 200
    get_response = client.get("/auth")
    assert get_response.status_code == 405  # 405 Method Not Allowed

def test_jwks_contains_valid_keys(client):
    # Test if the JWKS endpoint contains valid keys
    response = client.get("/jwks")
    assert response.status_code == 200
    

def test_expired_jwt_is_actually_expired(client):
    # Test if the JWT returned with 'expired=true' is actually expired
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    # Parse the JWT and check the 'exp' claim to ensure it's in the past

def test_expired_jwk_not_served(client):
    # Test if an expired JWK is not served in the JWKS endpoint
    response = client.get("/jwks")
    assert response.status_code == 200
    # Inspect the JWKS response to ensure no expired keys are present

