import os
import jwt
import datetime
from functools import wraps
from flask import request, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests
from database import get_user_by_email, create_user

from dotenv import load_dotenv
load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-123")

def verify_google_token(token):
    """Verifies a Google ID token or Access Token and returns the user info."""
    log_file = os.path.join(os.path.dirname(__file__), "auth_debug.log")
    
    with open(log_file, "a") as f:
        f.write(f"\n--- Auth Attempt {datetime.datetime.utcnow()} ---\n")
        if not GOOGLE_CLIENT_ID:
            f.write("ERROR: GOOGLE_CLIENT_ID is not set!\n")
            return None
            
        try:
            f.write(f"DEBUG: Verifying token prefix: {token[:20]}... (length: {len(token)})\n")
            
            # Check if it looks like a JWT (ID Token) or an Access Token
            if token.count('.') == 2:
                # ID Token
                f.write("DEBUG: Attempting ID Token verification\n")
                idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
                f.write(f"DEBUG: ID Token verified for email: {idinfo.get('email')}\n")
            else:
                # Access Token - fetch from userinfo
                f.write("DEBUG: Attempting Access Token verification via userinfo\n")
                import requests as py_requests
                userinfo_res = py_requests.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if not userinfo_res.ok:
                    f.write(f"ERROR: UserInfo fetch failed: {userinfo_res.text}\n")
                    return None
                idinfo = userinfo_res.json()
                # Map userinfo fields to standard idinfo fields
                idinfo['sub'] = idinfo.get('sub', idinfo.get('id', ''))
                f.write(f"DEBUG: Access Token verified for email: {idinfo.get('email')}\n")
            
            # User details from Google (common for both flows)
            email = idinfo['email']
            name = idinfo.get('name', '')
            picture = idinfo.get('picture', '')
            google_id = idinfo['sub']
            
            # Get or create user in MongoDB
            user = get_user_by_email(email)
            if not user:
                user = create_user({
                    "email": email,
                    "name": name,
                    "picture": picture,
                    "google_id": google_id
                })
                
            return user
        except Exception as e:
            f.write(f"Error verifies Google token: {e}\n")
            import traceback
            traceback.print_exc(file=f)
            return None

def generate_jwt(user):
    """Generates a JWT for the authenticated user."""
    payload = {
        "user_id": str(user.get("_id") or user.get("id")),
        "email": user["email"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Get token from Authorization header or query param (for SSE)
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        elif "token" in request.args:
            token = request.args.get("token")
        
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            # Add user_id to the request object for use in the endpoint
            request.user_id = data["user_id"]
            request.user_email = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401
            
        return f(*args, **kwargs)
    
    return decorated

if __name__ == "__main__":
    print("Auth logic checked.")
