from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class IconCreate(BaseModel):
    name: str
    icon_url: str

class IconResponse(BaseModel):
    id: int
    name: str
    icon_url: str

class ForgotPassword(BaseModel):
    username: str
    email: EmailStr

class ChangePasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
