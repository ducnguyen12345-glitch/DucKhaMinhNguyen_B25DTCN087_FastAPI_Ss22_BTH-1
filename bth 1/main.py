from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY chưa được cấu hình trong file .env")

ALGORITHM = "HS256"

app = FastAPI()

security = HTTPBearer()

users = {}


class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    password_bytes = password.encode("utf-8")
    hashed_password_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=30)

    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return token


@app.post("/api/register")
def register(user: UserRegister):
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = hash_password(user.password)
    users[user.username] = {"username": user.username,"hashed_password": hashed_password}
    return {
        "message": "Register successful",
        "username": user.username
    }


@app.post("/api/login")
def login(user: UserLogin):
    db_user = users.get(user.username)
    if not db_user:
        raise HTTPException(status_code=401,detail="Invalid username or password")

    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401,detail="Invalid username or password")

    access_token = create_access_token(user.username)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get("sub")

        if not username:
            raise HTTPException(status_code=401,detail="Invalid token")

        return username

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401,detail="Token has expired")

    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401,detail="Invalid token")


@app.get("/api/profile")
def profile(username: str = Depends(get_current_user)):
    return {
        "message": f"Welcome, {username}!"
    }


# 1
# Response body
# {
#   "message": "Register successful",
#   "username": "duc"
# }

# 2
# Response body
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkdWMiLCJpYXQiOjE3ODY5NzYxNDcsImV4cCI6MTc4Njk3Nzk0N30.8tKcaP56F2QCtrAPOD5GhRYax7jtBBQXf3yuOL46tSA",
#   "token_type": "bearer"
# }

# 3
# Response body
# {
#   "message": "Welcome, duc!"
# }