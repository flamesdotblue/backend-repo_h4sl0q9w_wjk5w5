import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

from database import db, create_document, get_documents

APP_NAME = "TradePortal"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title=f"{APP_NAME} API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------- Schemas -----------------------
RoleType = Literal["broker", "business", "individual", "admin"]

class SignupPayload(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: RoleType

class LoginPayload(BaseModel):
    email: EmailStr
    password: str

class OAuthPayload(BaseModel):
    provider: Literal["google", "linkedin"]
    email: EmailStr
    name: Optional[str] = None
    external_id: Optional[str] = None

class VerifyRequestPayload(BaseModel):
    email: EmailStr

class VerifyConfirmPayload(BaseModel):
    token: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: RoleType
    email_verified: bool
    name: Optional[str] = None

# ----------------------- Helpers -----------------------

def hash_password(p: str) -> str:
    return pwd_context.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)

def create_access_token(subject: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = subject.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

async def get_user_by_email(email: str) -> Optional[dict]:
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db["user"].find_one({"email": email.lower()})

# ----------------------- Routes -----------------------

@app.get("/")
def root():
    return {"message": f"{APP_NAME} Backend Running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_name"] = getattr(db, 'name', None)
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:100]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

@app.post("/auth/signup", response_model=TokenResponse)
async def signup(payload: SignupPayload):
    existing = await get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": payload.name,
        "email": payload.email.lower(),
        "role": payload.role,
        "email_verified": False,
        "password_hash": hash_password(payload.password),
        "providers": [],
    }
    create_document("user", doc)
    token = create_access_token({"sub": payload.email.lower(), "role": payload.role})
    return TokenResponse(access_token=token, role=payload.role, email_verified=False, name=payload.name)

@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginPayload):
    user = await get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user["email"], "role": user["role"]})
    return TokenResponse(access_token=token, role=user["role"], email_verified=bool(user.get("email_verified")), name=user.get("name"))

@app.post("/auth/verify/request")
async def request_verification(payload: VerifyRequestPayload):
    user = await get_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    token = create_access_token({"sub": user["email"], "scope": "verify"}, timedelta(hours=24))
    # In production, send via email provider. For demo, return token.
    return {"message": "Verification link generated", "token": token}

@app.post("/auth/verify/confirm")
async def confirm_verification(payload: VerifyConfirmPayload):
    try:
        data = jwt.decode(payload.token, JWT_SECRET, algorithms=[JWT_ALG])
        if data.get("scope") != "verify":
            raise HTTPException(status_code=400, detail="Invalid token scope")
        email = data.get("sub")
        db["user"].update_one({"email": email}, {"$set": {"email_verified": True, "updated_at": datetime.now(timezone.utc)}})
        return {"message": "Email verified"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/auth/password/request")
async def password_request(payload: PasswordResetRequest):
    user = await get_user_by_email(payload.email)
    if not user:
        # Do not reveal user existence
        return {"message": "If the account exists, a reset link has been generated"}
    token = create_access_token({"sub": user["email"], "scope": "reset"}, timedelta(hours=1))
    return {"message": "Reset link generated", "token": token}

@app.post("/auth/password/confirm")
async def password_confirm(payload: PasswordResetConfirm):
    try:
        data = jwt.decode(payload.token, JWT_SECRET, algorithms=[JWT_ALG])
        if data.get("scope") != "reset":
            raise HTTPException(status_code=400, detail="Invalid token scope")
        email = data.get("sub")
        db["user"].update_one({"email": email}, {"$set": {"password_hash": hash_password(payload.new_password), "updated_at": datetime.now(timezone.utc)}})
        return {"message": "Password updated"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/auth/oauth", response_model=TokenResponse)
async def oauth_login(payload: OAuthPayload):
    # In production, validate auth code / id token with provider APIs.
    # For demo, trust the provided email and external_id.
    user = await get_user_by_email(payload.email)
    if not user:
        role: RoleType = "business"  # default role for social sign-in
        doc = {
            "name": payload.name or payload.email.split("@")[0],
            "email": payload.email.lower(),
            "role": role,
            "email_verified": True,
            "password_hash": "",
            "providers": [{"provider": payload.provider, "external_id": payload.external_id}],
        }
        create_document("user", doc)
        user = await get_user_by_email(payload.email)
    token = create_access_token({"sub": user["email"], "role": user["role"]})
    return TokenResponse(access_token=token, role=user["role"], email_verified=bool(user.get("email_verified")), name=user.get("name"))

# Protected sample route
@app.get("/me")
async def me(token: str = Depends(oauth2_scheme)):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email = data.get("sub")
        user = await get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {"email": user["email"], "name": user.get("name"), "role": user.get("role"), "email_verified": user.get("email_verified", False)}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
