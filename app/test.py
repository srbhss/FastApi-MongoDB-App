from fastapi.testclient import TestClient
from .main import app


client = TestClient(app)


from .user import create_access_token, Token

validfaketoken = Token(access_token = create_access_token(email="abc@z.com"), token_type = "bearer")


def test_signup():
    response = client.post(
        "/user/signup/",
        json={"email": "abc@z.com", "password": "abc"},
    )
    assert response.status_code == 200
    assert response.json() == {"email": "abc@z.com"}
    

def test_valid_login():
    response = client.post(
        "/user/login/",
        json={"email": "abc@z.com", "password": "abc"},
    )
    assert response.status_code == 200
    assert response.json() == validfaketoken.json()


def test_invalid_login():
    response = client.post(
        "/user/login/",
        json={"email": "abc@z.com", "password": "xyz"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail":"Incorrect username or password"}