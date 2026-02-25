from fastapi.testclient import TestClient
from src.main import app
from src.models.User import LoginResponse

def test_create_user(client: TestClient, admin_token: LoginResponse):
    user_data = {
        "user_name": "new_integration_user",
    }
    
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    
    response = client.post("/api/users/", json=user_data, headers=headers)
    assert response.status_code == 201
    data = response.json()
    print(f"DEBUG: {data}")
    assert data["user_name"] == user_data["user_name"]
    # Removed assertions for id, hash_password, salt as they are not returned

def test_create_duplicate_user(client: TestClient, admin_token: LoginResponse):
    user_data = {
        "user_name": "duplicate_test_user",
    }
    
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    
    # First creation
    response = client.post("/api/users/", json=user_data, headers=headers)
    assert response.status_code == 201
    
    # Second creation (should fail)
    response = client.post("/api/users/", json=user_data, headers=headers)
    assert response.status_code == 409

def test_get_users(client: TestClient, admin_token: LoginResponse):
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    # Ensure we have at least one user (created above or previously)
    response = client.get("/api/users/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # We can't strictly assert length because of other tests, but we can check if our user is there if we want, 
    # but for now just checking it returns a list is a good basic test.

def test_activate_user(client: TestClient, admin_token: LoginResponse):
    # 1. Create a user
    user_data = {
        "user_name": "activation_test_user",
    }
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    create_response = client.post("/api/users/", json=user_data, headers=headers)
    assert create_response.status_code == 201
    created_user = create_response.json()
    password = created_user["password"]
    
    # 2. Activate the user
    activate_data = {
        "user_name": "activation_test_user",
        "password": "new_secure_password",
        "one_time_password": password,
        "assymetric_public_key": "test_public_key_123"
    }
    
    response = client.post("/api/auth/activate", json=activate_data)
    assert response.status_code == 200
    data = response.json()
    
    assert data["user_name"] == "activation_test_user"
    assert data["assymetric_public_key"] == "test_public_key_123"

def test_get_user_info(client: TestClient, admin_token: LoginResponse):
    # 1. Create a user
    user_data = {
        "user_name": "info_test_user",
    }
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    create_response = client.post("/api/users/", json=user_data, headers=headers)
    assert create_response.status_code == 201
    created_user = create_response.json()
    password = created_user["password"]
    
    # 2. Activate User
    activate_data = {
        "user_name": "info_test_user",
        "password": "new_secure_password",
        "one_time_password": password,
        "assymetric_public_key": "test_public_key_info"
    }
    client.post("/api/auth/activate", json=activate_data)

    # 3. Login to get token
    login_data = {
        "user_name": "info_test_user",
        "password": "new_secure_password"
    }
    login_response = client.post("/api/auth/login", json=login_data)
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # 3. Get user info
    response = client.get("/api/user/me/info", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    
    assert data["user_name"] == "info_test_user"
    assert "id" in data
    assert "id" in data
    # assert "assymetric_public_key" in data # Removed from UserInfoResponse
    assert "last_login" in data
    
    # checks that sensitive data is not returned
    assert "hash_password" not in data
    assert "salt" not in data
    assert "blob" not in data

def test_update_user_info(client: TestClient, admin_token: LoginResponse):
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    # 1. Create a user
    response = client.post("/api/users", json={"user_name": "update_test_user"}, headers=headers)
    assert response.status_code == 201
    user_data = response.json()
    original_password = user_data["password"]
    
    # 2. Activate User
    activate_data = {
        "user_name": "update_test_user",
        "password": "new_secure_password",
        "one_time_password": original_password,
        "assymetric_public_key": "test_public_key_update"
    }
    client.post("/api/auth/activate", json=activate_data)

    # 3. Login to get token
    login_response = client.post("/api/auth/login", json={"user_name": "update_test_user", "password": "new_secure_password"})
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Update password
    new_password = "new_secure_password_123"
    update_response = client.post("/api/user/me/info", json={"password": new_password}, headers=headers)
    assert update_response.status_code == 200
    
    # 4. Verify login with old password fails (the activated password before update)
    fail_login = client.post("/api/auth/login", json={"user_name": "update_test_user", "password": "activated_password_123"})
    assert fail_login.status_code == 401
    
    # 5. Verify login with new password succeeds
    success_login = client.post("/api/auth/login", json={"user_name": "update_test_user", "password": new_password})
    assert success_login.status_code == 200

def test_update_user_info_duplicate_username(client: TestClient, admin_token: LoginResponse):
    headers = {
        "Authorization": f"Bearer {admin_token.access_token}",
        "X-Role-Token": admin_token.role_tokens["ADMINISTRATOR"].signature
    }
    # 1. Create user A
    client.post("/api/users", json={"user_name": "user_A"}, headers=headers)
    
    # 2. Create user B
    response_b = client.post("/api/users", json={"user_name": "user_B"}, headers=headers)
    user_b_data = response_b.json()
    password_b = user_b_data["password"]
    
    # 3. Activate User B
    activate_data = {
        "user_name": "user_B",
        "password": "new_secure_password_b",
        "one_time_password": password_b,
        "assymetric_public_key": "test_public_key_b"
    }
    client.post("/api/auth/activate", json=activate_data)

    # 4. Login as user B
    login_response = client.post("/api/auth/login", json={"user_name": "user_B", "password": "new_secure_password_b"})
    token_b = login_response.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    
    # 4. Try to update user B's name to "user_A"
    update_response = client.post("/api/user/me/info", json={"user_name": "user_A"}, headers=headers_b)
    assert update_response.status_code == 409
    
    # 5. Verify user B is still "user_B"
    info_response = client.get("/api/user/me/info", headers=headers_b)
    assert info_response.status_code == 200
    info_data = info_response.json()
    assert info_data["user_name"] == "user_B"
