from pydantic import BaseModel, EmailStr
from typing import Optional

# Schema for user creation
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    class Config:
        orm_mode = True

# Schema for user login
class UserLogin(BaseModel):
    username: str
    password: str

# Schema for password reset
class PasswordReset(BaseModel):
    username: str
    new_password: str

# Schema for forgot password request
class ForgotPassword(BaseModel):
    username: str
    email: EmailStr

# Schema for OTP verification
class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

# Schema for token verification
class TokenData(BaseModel):
    token: str

# Schema for user response (e.g., in signup or reset password)
class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True
class ChangePasswordRequest(BaseModel):
    new_password: str
