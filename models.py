from typing import Optional
from pydantic import BaseModel, EmailStr

class Register(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    password: str


class Login(BaseModel):
    email: str
    password: str

class Update(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class LoginWithOTP(BaseModel):
    phone: str