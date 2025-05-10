import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------------------- Session State Initialization ----------------------
if "data_store" not in st.session_state:
    st.session_state.data_store = {}

if "login_required" not in st.session_state:
    st.session_state.login_required = False

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "page" not in st.session_state:
    st.session_state.page = "home"

# 🔐 Store Fernet key only once (prevents decryption errors)
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

fernet = Fernet(st.session_state.fernet_key)

# ---------------------- Hashing Function ----------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# ---------------------- Login Page ----------------------
def login_page():
    st.title("🔐 Login Required")
    password = st.text_input("Enter Admin Password", type="password")
    if st.button("Login"):
        if password == "admin123":
            st.session_state.login_required = False
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully.")
            st.session_state.page = "home"
        else:
            st.error("Wrong admin password.")

# ---------------------- Home Page ----------------------
def home_page():
    st.title("🛡️ Secure Data Encryption System")
    st.write("Choose an action:")
    if st.button("Store New Data"):
        st.session_state.page = "store"
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"

# ---------------------- Store Data Page ----------------------
def store_data_page():
    st.title("📥 Store New Data")
    username = st.text_input("Username")
    text = st.text_area("Enter your data")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Encrypt & Store"):
        if username and text and passkey:
            hashed = hash_passkey(passkey)
            encrypted_text = fernet.encrypt(text.encode()).decode()
            st.session_state.data_store[username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed
            }
            st.success("Data stored securely.")
        else:
            st.warning("Please fill all fields.")

# ---------------------- Retrieve Data Page ----------------------
def retrieve_data_page():
    st.title("🔓 Retrieve Encrypted Data")
    username = st.text_input("Username")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt Data"):
        if username in st.session_state.data_store:
            hashed_input = hash_passkey(passkey)
            stored_entry = st.session_state.data_store[username]
            if hashed_input == stored_entry["passkey"]:
                decrypted = fernet.decrypt(stored_entry["encrypted_text"].encode()).decode()
                st.success(f"Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Attempt {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.login_required = True
                    st.session_state.page = "login"
        else:
            st.warning("No data found for this username.")

# ---------------------- Page Routing ----------------------
if st.session_state.login_required:
    login_page()
elif st.session_state.page == "home":
    home_page()
elif st.session_state.page == "store":
    store_data_page()
elif st.session_state.page == "retrieve":
    retrieve_data_page()

# ---------------------- Navigation Back Button ----------------------
if st.session_state.page != "home" and not st.session_state.login_required:
    if st.button("⬅️ Back to Home"):
        st.session_state.page = "home"
