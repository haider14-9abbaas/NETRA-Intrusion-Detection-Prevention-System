# services/auth.py
from __future__ import annotations

import os
import streamlit as st
from config import SESSION_TTL_SECONDS, SESSION_ROTATE_ON_LOGIN
from utils.security import now_ts, new_csrf_token, verify_password, hash_password

AUTH_KEY = "ids_auth_v2"
CSRF_KEY = "ids_csrf_v1"

# Demo users:
# In prod: store hashes in env vars or secured storage (not in code).
# You can generate hash once:
#   python -c "from utils.security import hash_password; print(hash_password('admin123'))"
USERS = {
    "admin": {
        "role": "admin",
        "password_hash": os.getenv("IDS_ADMIN_HASH") or hash_password("admin123"),
    },
    "viewer": {
        "role": "viewer",
        "password_hash": os.getenv("IDS_VIEWER_HASH") or hash_password("viewer123"),
    },
}

def _expired(auth: dict) -> bool:
    if not auth:
        return True
    exp = auth.get("expires_at", 0)
    return now_ts() > int(exp)

def require_login():
    if AUTH_KEY not in st.session_state:
        st.session_state[AUTH_KEY] = None

    auth = st.session_state.get(AUTH_KEY)
    if auth and not _expired(auth):
        return auth

    if auth and _expired(auth):
        st.session_state[AUTH_KEY] = None
        st.sidebar.warning("Session expired. Please login again.")

    st.sidebar.subheader("🔐 Login")
    u = st.sidebar.text_input("Username", key="login_user").strip()
    p = st.sidebar.text_input("Password", type="password", key="login_pass")
    btn = st.sidebar.button("Login", use_container_width=True)

    if btn:
        if u in USERS and verify_password(p, USERS[u]["password_hash"]):
            expires_at = now_ts() + int(SESSION_TTL_SECONDS)

            # Rotate/refresh CSRF token on login
            if SESSION_ROTATE_ON_LOGIN or CSRF_KEY not in st.session_state:
                st.session_state[CSRF_KEY] = new_csrf_token()

            st.session_state[AUTH_KEY] = {
                "username": u,
                "role": USERS[u]["role"],
                "login_at": now_ts(),
                "expires_at": expires_at,
            }
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")

    st.stop()

def logout_button():
    auth = st.session_state.get(AUTH_KEY)
    if auth and not _expired(auth):
        st.sidebar.caption(f"Logged in as: **{auth.get('username')}** ({auth.get('role')})")
        if st.sidebar.button("Logout", use_container_width=True):
            st.session_state[AUTH_KEY] = None
            st.rerun()

def is_admin() -> bool:
    auth = st.session_state.get(AUTH_KEY) or {}
    return auth.get("role") == "admin"

def get_csrf_token() -> str:
    if CSRF_KEY not in st.session_state:
        st.session_state[CSRF_KEY] = new_csrf_token()
    return st.session_state[CSRF_KEY]

def require_csrf(token: str) -> bool:
    return token and token == get_csrf_token()