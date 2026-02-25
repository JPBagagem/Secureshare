from https import requests_ as requests
import json
import os
import base64
import jwt
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import getpass

BASE_URL = "https://localhost/api"
TOKEN = None
ROLES = {}
CLEARANCE_TOKENS = {}
CURRENT_USER = None
BUF_SIZE = 65536


# =========================
#      UTILITY FUNCTIONS
# =========================
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def yes_or_no(question):
    resp = input(f"{question} (y/n): ").lower()
    return resp == "y" or resp == "yes" or resp == ""


def get_int_input(prompt, allow_empty=False):
    """Helper to get validated integer input from user.
    
    Args:
        prompt: The prompt to display to the user
        allow_empty: If True, returns None on empty input instead of requiring a number
    
    Returns:
        int or None (if allow_empty and user entered empty string)
    """
    while True:
        value = input(prompt)
        if allow_empty and value.strip() == "":
            return None
        try:
            return int(value)
        except ValueError:
            print("Invalid input. Please enter a valid number.")


def validate_password(password):
    """Validate password strength.
    
    Requirements:
        - At least 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, None


def get_secure_password(prompt="Password: ", allow_empty=False):
    """Get a validated password from user.
    
    Args:
        prompt: The prompt to display
        allow_empty: If True, allows empty password (for optional updates)
    
    Returns:
        str: The validated password, or empty string if allow_empty and user skipped
    """
    while True:
        password = getpass.getpass(prompt)
        if allow_empty and password.strip() == "":
            return ""
        is_valid, error = validate_password(password)
        if is_valid:
            return password
        print(f"Weak password: {error}")

def get_clearence_token(head, deps, level, isWrite):

    clearance_order = {
            "UNCLASSIFIED": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4
        }
    
    global CLEARANCE_TOKENS
    
    if isWrite:

        for token in CLEARANCE_TOKENS:
            if clearance_order[level]>=clearance_order[token["clearance_name"]]:
                valid=True
                for cl_dep in token["departments"]:
                    if str(cl_dep) not in deps:
                        valid=False
                        break
                if valid:
                    head["X-Clearance-Token"] = token["signature"]
                return
            
    for token in CLEARANCE_TOKENS:
        if clearance_order[level]<=clearance_order[token["clearance_name"]]:
            valid=True
            for cl_dep in deps:
                if int(cl_dep) not in token["departments"]:
                    valid=False
                    break
            if valid:
                head["X-Clearance-Token"] = token["signature"]
            return

    return head


def auth_header(roles=[], deps=[], level="", isWrite=True):
    head={}
    if TOKEN:
        head["Authorization"] = f"Bearer {TOKEN}"

    for role in roles:
        if role in ROLES:
            head["X-Role-Token"] = ROLES[role]["signature"]
            break

    if level!="":
        get_clearence_token(head, deps, level, isWrite)

    return head

def select_options(options_list):
    while True:

        for i, op in enumerate(options_list):
            print(f"{i+1}. {op}")
        print("0. " + "BACK")
        op = input("> ")
        try:
            op = int(op)
        except ValueError:
            print("Invalid option. Please try again.")
            input("Press Enter to continue...")
            continue
        if op == 0: return
        elif op < 1 or op > len(options_list):
            print("Invalid option. Please try again.")
            input("Press Enter to continue...")
            continue
        return options_list[op-1]


def get_user_private_key():
    if not CURRENT_USER:
        print("Error: No user logged in.")
        return None

    password = CURRENT_USER["password"]

    try:
        r = requests.get(f"{BASE_URL}/users/me/vault", headers=auth_header())
        
        if r.status_code == 200 and r.json().get("blob"):
            blob_b64 = r.json()["blob"]
            blob = base64.b64decode(blob_b64)
            
            salt = blob[:16]
            nonce = blob[16:28]
            ciphertext = blob[28:-16]
            tag = blob[-16:]
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(password.encode())
            
            decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag)).decryptor()
            pem_data = decryptor.update(ciphertext) + decryptor.finalize()
        
                
            
            print("Private key retrieved from vault successfully!", flush=True)
            
            
            return serialization.load_pem_private_key(pem_data, password=None)

        else:
            print(f"DEBUG: Vault response invalid or no blob. Body: {r.text}", flush=True)
    except Exception as e:
        print(f"DEBUG: Exception during vault request: {str(e)}", flush=True)

    # 3. Key not found
    print("Key not found in vault.", flush=True)
    return None


# =========================
#       USER ACTIONS
# =========================
def activate_user():
    username = input("Username: ")
    otp = input("One-time Password: ")
    new_pass = get_secure_password("New password: ")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    payload = {
        "user_name": username,
        "one_time_password": otp,
        "password": new_pass,
        "assymetric_public_key": public_pem.decode()
    }

    r = requests.post(f"{BASE_URL}/auth/activate", json=payload)
    if r.status_code == 200:
        print("User activated successfully!")
        
        # Auto-upload to vault
        # 1. Login to get token
        r_login = requests.post(f"{BASE_URL}/auth/login", json={"user_name": username, "password": new_pass})
        if r_login.status_code == 200:
            temp_token = r_login.json()["access_token"]
            
            # Encrypt private key for vault
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(new_pass.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(pem) + encryptor.finalize()
            tag = encryptor.tag
            
            blob_bytes = salt + nonce + ciphertext + tag
            blob = base64.b64encode(blob_bytes).decode()

            # 2. Upload to vault
            r_vault = requests.put(
                f"{BASE_URL}/users/me/vault", 
                json={"blob": blob}, 
                headers={"Authorization": f"Bearer {temp_token}"}
            )
            
            if r_vault.status_code == 200:
                print("Encrypted private key saved to vault.")
            else:
                print(f"Warning: Failed to upload key to vault: {r_vault.text}")
                
            # 3. Logout (optional, but good practice to clean up)
            requests.post(f"{BASE_URL}/auth/logout", headers={"Authorization": f"Bearer {temp_token}"})
            
        else:
             print("Warning: Could not login to upload key to vault.")

    else:
        print("Activation failed:", r.json()["detail"])


def login():
    global TOKEN, CURRENT_USER, ROLES, CLEARANCE_TOKENS
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    r = requests.post(f"{BASE_URL}/auth/login", json={"user_name": username, "password": password})
    if r.status_code == 200:
        TOKEN = r.json()["access_token"]
        CURRENT_USER = {"username": username, "password": password}
        print("Logged in successfully!")
        ROLES = r.json()["role_tokens"]
        CLEARANCE_TOKENS = r.json()["clearance_tokens"]
        # Ensure key is ready
        get_user_private_key()
    else:
        try:
            print("Login failed:", r.json()["detail"])
        except:
            print("Login failed:", r.text)


def logout():
    r = requests.post(f"{BASE_URL}/auth/logout", headers=auth_header())
    global TOKEN, CURRENT_USER
    TOKEN = None
    CURRENT_USER = None
    try:
        data = r.json()
        if "message" in data:
            print(data["message"])
        else:
            print("Logout failed:", data["detail"])
    except:
        print("Logout failed:", r.text)


def info():
    r = requests.get(f"{BASE_URL}/user/me/info", headers=auth_header())
    print()
    for k, v in r.json().items():
        print(f"{k}: {v}")


def create_user():
    username = input("Username: ")
    r = requests.post(f"{BASE_URL}/users", json={"user_name": username}, headers=auth_header(roles=["ADMINISTRATOR"]))
    if r.status_code == 201:
        print("User created successfully!")
        print("ID: " + str(r.json()["id"]))
        print("One-time password: " + r.json()["password"])
    else:
        print("Failed to create user:", r.json()["detail"])

def list_users():
    r = requests.get(f"{BASE_URL}/users", headers=auth_header(roles=["ADMINISTRATOR", "SECURITY_OFFICER"]))
    print(r.status_code, json.dumps(r.json(), indent=2))


def get_vault():
    r = requests.get(f"{BASE_URL}/users/me/vault", headers=auth_header())
    print(r.status_code, r.json())


def update_user_info():
    username = input("New username (leave empty to skip): ")
    password = get_secure_password("New password (leave empty to skip): ", allow_empty=True)
    global CURRENT_USER
    if not CURRENT_USER:
        print("Error: No user logged in.")
        return None
    payload = {}
    if username: 
        payload["user_name"] = username
        CURRENT_USER["user_name"]= username
    if password: 
        payload["password"] = password
        private_key = get_user_private_key()
        CURRENT_USER["password"]= password
        
    r = requests.post(f"{BASE_URL}/user/me/info", json=payload, headers=auth_header())
    print(r.status_code, r.json())
    
    if r.status_code == 200:

        if not password:
            return
        
        r_login = requests.post(f"{BASE_URL}/auth/login", json={"user_name": CURRENT_USER["username"], "password": CURRENT_USER["password"]})
        if r_login.status_code == 200:
            temp_token = r_login.json()["access_token"]
            
            # Encrypt private key for vault
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            kdf = Argon2id(
                salt=salt,
                length=32,
                iterations=3,
                lanes=4,
                memory_cost=262144
            )
            aes_key = kdf.derive(password.encode())
            
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()

            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            ciphertext = encryptor.update(private_key_bytes) + encryptor.finalize()
            tag = encryptor.tag
            
            blob_bytes = salt + nonce + ciphertext + tag
            blob = base64.b64encode(blob_bytes).decode()

            # 2. Upload to vault
            r_vault = requests.put(
                f"{BASE_URL}/users/me/vault", 
                json={"blob": blob}, 
                headers={"Authorization": f"Bearer {temp_token}"}
            )
            
            if r_vault.status_code != 200:
                print(f"Warning: Failed to upload key to vault: {r_vault.text}")
            
        else:
             print("Warning: Could not login to upload key to vault.")

    else:
        print("Update failed:", r.json()["detail"])


def add_role():
    user_id = get_int_input("Target User ID: ")
    role_type = select_options(["SECURITY_OFFICER", "TRUSTED_OFFICER", "AUDITOR"])
    if not role_type:
        return
    if role_type == "TRUSTED_OFFICER":
        dept_id_input = get_int_input("Department ID (optional): ", allow_empty=True)
        dept_id = int(dept_id_input) if dept_id_input else None
    else:
        dept_id = None
    
    
    private_key = get_user_private_key()
    if not private_key: return
    
    # Get current user ID from token or info
    me = requests.get(f"{BASE_URL}/user/me/info", headers=auth_header()).json()
    granter_id = me["id"]
    
    issued_at = int(datetime.now(timezone.utc).timestamp())
    
    payload = {
        "sub": str(user_id),
        "role_type": role_type,
        "dept_id": dept_id,
        "iss": str(granter_id),
        "iat": issued_at
    }
    
    signature = jwt.encode(payload, private_key, algorithm="RS256")
    
    data = {
        "signature": signature,
    }
    
    r = requests.put(f"{BASE_URL}/users/{user_id}/role", json=data, headers=auth_header(roles=["ADMINISTRATOR", "SECURITY_OFFICER"]))
    print(r.status_code, r.json())


def revoke_role():
    try:
        user_id = int(input("Target User ID: "))
        token_id = int(input("Token ID to revoke: "))
    except ValueError:
        print("Error: User ID and Token ID must be valid integers.")
        return
    
    private_key = get_user_private_key()
    if not private_key: return
    
    me = requests.get(f"{BASE_URL}/user/me/info", headers=auth_header()).json()
    revoker_id = me["id"]

    revoked_at = datetime.now(timezone.utc)
    
    payload = {
        "sub": str(token_id),
        "iss": str(revoker_id),
        "iat": revoked_at
    }
    
    signature = jwt.encode(payload, private_key, algorithm="RS256")
    
    data = {
        "signature": signature,
        "revoked_at": revoked_at.isoformat()
    }
    
    r = requests.put(f"{BASE_URL}/users/{user_id}/revoke/{token_id}", json=data, headers=auth_header(roles=["SECURITY_OFFICER"]))
    print(r.status_code, r.json())


def delete_user():
    user_id = input("User ID to delete: ")
    r = requests.delete(f"{BASE_URL}/users/{user_id}", headers=auth_header(roles=["ADMINISTRATOR"]))
    print(r.status_code)


def get_clearance():
    user_id = input("User ID: ")
    r = requests.get(f"{BASE_URL}/users/{user_id}/clearance", headers=auth_header(roles=["SECURITY_OFFICER"]))
    print(r.status_code, json.dumps(r.json(), indent=2))


def add_clearance():
    user_id = get_int_input("Target User ID: ")
    clearance_type = select_options(["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
    if not clearance_type:
        return
    
    try:
        dept_ids = [int(x) for x in input("Department IDs (comma separated): ").split(",") if x.strip()]
    except ValueError:
        print("Error: Department IDs must be valid integers.")
        return
    
    private_key = get_user_private_key()
    if not private_key: return
    
    me = requests.get(f"{BASE_URL}/user/me/info", headers=auth_header(roles=["SECURITY_OFFICER"])).json()
    granter_id = me["id"]
    
    issued_at = int(datetime.now(timezone.utc).timestamp())
    
    payload = {
        "sub": str(user_id),
        "iss": str(granter_id),
        "clearance_type": clearance_type,
        "dept_ids": dept_ids,
        "iat": issued_at,
        "exp": issued_at + 3600 * 24 * 365 # 1 year expiration
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    data = {
        "token": token
    }
    
    r = requests.put(f"{BASE_URL}/users/{user_id}/clearance", json=data, headers=auth_header(roles=["SECURITY_OFFICER"]))
    print(r.status_code, r.json())


# =========================
#    DEPARTMENT ACTIONS
# =========================
def dep_get():
    r = requests.get(f"{BASE_URL}/departments/", headers=auth_header())
    print(r.status_code, r.json())


def dep_add():
    name = input("Department name: ")
    r = requests.post(f"{BASE_URL}/departments/", json={"name": name}, headers=auth_header())
    print(r.status_code, r.json())


def dep_delete():
    dep_id = input("Department ID to delete: ")
    r = requests.delete(f"{BASE_URL}/departments/{dep_id}", headers=auth_header())
    print(r.status_code, r.json())


# =========================
#      AUDIT ACTIONS
# =========================
def get_logs():
    r = requests.get(f"{BASE_URL}/audit/log", headers=auth_header())
    print(r.status_code, json.dumps(r.json(), indent=2))


def sign_log():
    log_id = input("Log ID to sign: ")
    try:
        log_id = int(log_id)
        r = requests.get(f"{BASE_URL}/audit/log", headers=auth_header())
        if r.status_code != 200:
            print("Failed to fetch logs")
            return
    except ValueError:
        print("Error: log_id must be a valid integer")
        return
    except Exception as e:
        print(f"Error fetching logs: {e}")
        return
    # Get logs to find the hash
        
    logs = r.json().get("Logs", [])
    target_log = next((l for l in logs if l["id"] == log_id), None)
    
    if not target_log:
        print("Log not found")
        return
        
    current_hash = target_log["current_hash"]
    
    private_key = get_user_private_key()
    if not private_key: return
    
    signature = private_key.sign(
        current_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    data = {
        "log_id": log_id,
        "signature": base64.b64encode(signature).decode()
    }
    
    r = requests.put(f"{BASE_URL}/audit/validate", data=data, headers=auth_header())
    print(r.status_code, r.json())


# =========================
#       FILE ACTIONS
# =========================
def auxiliar_shared(file_uid, user_id, aes_key):
    try:
        resp = requests.get(f"{BASE_URL}/users/{user_id}/key", headers=auth_header())
        if resp.status_code != 200:
            print(f"Error: Failed to get public key for user {user_id}: {resp.status_code}")
            return None
        key_data = resp.json().get("assymetric_public_key")
        if not key_data:
            print(f"Error: User {user_id} has no public key.")
            return None
        public_key = serialization.load_pem_public_key(key_data.encode())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        r = requests.post(f"{BASE_URL}/transfers/share/", headers=auth_header(), data={
            "file_uid": file_uid,
            "user_share_id": user_id,
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode()
        })
        return r
    except Exception as e:
        print(f"Error sharing file with user {user_id}: {e}")
        return None


def file_upload():
    filepath = input("Path to file: ")
    clearance = select_options(["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])
    if not clearance:
        return
    while True:
        priv_input = input("Private? (y/n): ").lower()
        if priv_input in ("y", "n"):
            is_priv = priv_input == "y"
            break
        print("Invalid input. Please enter 'y' or 'n'.")
    
    deps = input("Department IDs (comma separated): ")
    if is_priv:
        people_to_share = input("People IDs to share (comma separated): ")
    else:
        people_to_share = ""
    reason = input("Reason to acess: ")
    # Read file
    try:
        data = Path(filepath).read_bytes()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # Get user's public key
    try:
        user_info = requests.get(f"{BASE_URL}/user/me/info", headers=auth_header()).json()
        user_id = user_info["id"]
        key_resp = requests.get(f"{BASE_URL}/users/{user_id}/key", headers=auth_header()).json()
        if "assymetric_public_key" not in key_resp or not key_resp["assymetric_public_key"]:
            print("Error: Your user has no public key. Please activate your account first.")
            return
        public_key = serialization.load_pem_public_key(key_resp["assymetric_public_key"].encode())
    except KeyError as e:
        print(f"Error: Failed to get user info or public key: {e}")
        return
    except Exception as e:
        print(f"Error loading public key: {e}")
        return

    # Encrypt file with AES-GCM
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    # Encrypt AES key with user's public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    files = {"file": (os.path.basename(filepath), encrypted_data, "application/octet-stream")}
    data_payload = {
        "clearance_level": clearance,
        "is_private": str(is_priv).lower(),
        "department_list": deps,
        "aes_iv": base64.b64encode(iv).decode(),
        "aes_tag": base64.b64encode(tag).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode() if is_priv else None,
       "reason":"222"
    }

    deps_list=[]

    try:
        if deps.strip()!="":
            deps_list=deps.split(",")
    except:
        print("invalid dep input")
        return

    r = requests.post(f"{BASE_URL}/transfers/", headers=auth_header(roles=["TRUSTED_OFFICER"], deps=deps_list, level=clearance), files=files, data=data_payload)
    file_info = r.json()
    if "uid" not in file_info:
        print("File upload failed")
        print(file_info.get("details"))
        return
    if r.status_code==200:
        print("File uploaded with success!!!\nFile uuid: ", file_info["uid"])


    # Generate download link - for private files just use uid, for public files include the key
    if is_priv:
        print(f"Download Link: {BASE_URL}/download/{file_info['uid']}")
    else:
        print(f"Download Link: {BASE_URL}/download/{file_info['uid']}#{base64.b64encode(aes_key).decode()}")

    # Auto-share
    for p in [int(u.strip()) for u in people_to_share.split(",") if u.strip()]:
        resp = auxiliar_shared(file_info["uid"], p, aes_key)
        if resp:
            print(f"Shared with {p}: {resp.status_code}")
        else:
            print(f"Failed to share with {p}")
    

def download_public_file():
    file_url = input("URL to file: ")
    if "#" not in file_url:
        print("Missing key: URL must be /download/<id>#<BASE64_KEY>")
        return

    file_url_without_key, key_b64 = file_url.split("#", 1)
    aes_key = base64.b64decode(key_b64)
    clearance = select_options(["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])

    r = requests.get(file_url_without_key,headers=auth_header(clearances=[clearance]))
    if r.status_code != 200:
        print(f"Download failed: {r.status_code} {r.text}")
        return

    try:
        iv = base64.b64decode(r.headers.get("X-IV"))
        tag = base64.b64decode(r.headers.get("X-Tag"))
        file_name = r.headers.get("X-FileName")
        if not file_name:
            print("Error: Server did not return filename")
            return
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
        plaintext = decryptor.update(r.content) + decryptor.finalize()
        Path(file_name).write_bytes(plaintext)
        print(f"File {file_name} downloaded and decrypted successfully.")
    except Exception as e:
        print(f"Error decrypting file: {e}")


def file_share():
    file_uid = input("File UID to share: ")
    people_list = [int(u.strip()) for u in input("People IDs (comma separated): ").split(",") if u.strip()]
    file_info = requests.get(f"{BASE_URL}/transfers/{file_uid}", headers=auth_header()).json()

    file_info = requests.get(f"{BASE_URL}/transfers/{file_uid}", headers=auth_header()).json()

    private_key = get_user_private_key()
    if not private_key: return

    try:
        if not file_info.get("symetric_key_encrypted"):
            print("Error: File has no encrypted key (may be a public file)")
            return
        aes_key = private_key.decrypt(
            base64.b64decode(file_info["symetric_key_encrypted"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception as e:
        print(f"Error decrypting AES key: {e}")
        return

    for u in people_list:
        resp = auxiliar_shared(file_uid, u, aes_key)
        if resp:
            print(f"Shared with {u}: {resp.status_code}")
        else:
            print(f"Failed to share with {u}")


def file_list():
    r = requests.get(f"{BASE_URL}/transfers/", headers=auth_header())
    print(r.status_code, json.dumps(r.json(), indent=2))


def file_delete():
    file_uid = input("File UID to delete: ")
    r = requests.delete(f"{BASE_URL}/transfers/{file_uid}", headers=auth_header())
    print(r.status_code, r.json())


def download_file():
    transfer_uid = input("File UID to download: ")
    private_key = get_user_private_key()
    if not private_key: return
    clearance = select_options(["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"])

    file_info = requests.get(f"{BASE_URL}/transfers/{transfer_uid}", headers=auth_header()).json()
    if not file_info or file_info=={'detail': "File doesn't exist or you don't have permission"}:
        print("file not found  or you don't have permission")
        return
    print(file_info)
    r = requests.get(f"{BASE_URL}/download/{transfer_uid}", headers=auth_header(roles=["TRUSTED_OFFICER"], deps=file_info["departments"], level=file_info["clearance_name"], isWrite=False))
    if r.status_code != 200:
        print(f"Download failed: {r.status_code} {r.text}")
        return

    try:
        encrypted_key = base64.b64decode(r.headers.get("X-Encrypted-Key") or "")
        iv = base64.b64decode(r.headers.get("X-IV") or "")
        tag = base64.b64decode(r.headers.get("X-Tag") or "")
        file_name = r.headers.get("X-FileName")
        
        if not file_name:
            print("Error: Server did not return filename")
            return
        if not encrypted_key:
            print("Error: Server did not return encrypted key")
            return

        aes_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
        plaintext = decryptor.update(r.content) + decryptor.finalize()
        Path(file_name).write_bytes(plaintext)
        print(f"File {file_name} downloaded and decrypted successfully.")
    except Exception as e:
        print(f"Error decrypting file: {e}")


# =========================
#         MENU
# =========================

def menu(name : str, options : dict[str, callable], back_opt_name : str = "Back", final_menu : bool = True):
    options_list= list(options.keys())
    while True:
        clear()
        print(f"=== {name} MENU ===")

        for i, op in enumerate(options_list):
            print(f"{i+1}. {op}")
        print("0. " + back_opt_name)
        op = input("> ")
        try:
            op = int(op)
        except ValueError:
            print("Invalid option. Please try again.")
            input("Press Enter to continue...")
            continue
        if op == 0: return True
        elif op < 1 or op > len(options_list):
            print("Invalid option. Please try again.")
            input("Press Enter to continue...")
            continue
        options[options_list[op-1]]()
        if final_menu: 
            input("Press Enter to continue...")
        break
    


def menu_users():
    options = {
        "Activate user": activate_user,
        "Login": login,
        "Info": info,
        "Logout": logout,
        "Create User": create_user,
        "List Users": list_users,
        "Delete User": delete_user,
        "Update User Info": update_user_info,
        "Get Vault": get_vault,
        "Add Role": add_role,
        "Revoke Role": revoke_role,
        "Get Clearance": get_clearance,
        "Add Clearance": add_clearance,
    }
    
    menu("Users", options)


def menu_departments():
    options = {
        "List departments": dep_get,
        "Add department": dep_add,
        "Delete department": dep_delete
    }
    menu("Departments", options)


def menu_files():
    options = {
        "Upload file": file_upload,
        "List files": file_list,
        "Delete file": file_delete,
        "Share existing file": file_share,
        "Download file": download_file,
        "Dowload public file": download_public_file
    }
    menu("Files", options)


def menu_audit():
    options = {
        "Get Logs": get_logs,
        "Sign Log": sign_log
    }
    menu("Audit Logs", options)





# =========================
#          MAIN
# =========================
def main():
    while True:
        options = {
            "Users": menu_users,
            "Departments": menu_departments,
            "Files": menu_files,
            "Audit Logs": menu_audit
        }

        try:
            if menu("Main", options, back_opt_name="Exit", final_menu=False):
                break
        except EOFError as e:
            break


if __name__ == "__main__":
    main()
