from pydantic import BaseModel

# Define a Pydantic model for incoming signup requests
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

# Define a Pydantic model for login requests
class UserLogin(BaseModel):
    username: str
    password: str