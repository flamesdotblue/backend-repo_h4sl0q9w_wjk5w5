from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List

RoleType = Literal["broker", "business", "individual", "admin"]

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    role: RoleType = Field(..., description="User role")
    email_verified: bool = Field(False, description="Whether email is verified")
    password_hash: Optional[str] = Field(None, description="BCrypt password hash")
    providers: List[dict] = Field(default_factory=list, description="Linked OAuth providers")

class VerificationToken(BaseModel):
    email: EmailStr
    token: str
    purpose: Literal["verify", "reset"]

# You can add more domain schemas here as you build jobs, proposals, wallets, etc.
