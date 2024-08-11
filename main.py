from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta
import bcrypt
import jwt

from models import User
from schemas import UserCreate , UserLogin , PasswordReset
from database import engine, Base, get_db

# Initialize FastAPI app
app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)

# Secret key to encode JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30



# Function to create JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to hash password
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Function to verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Signup route
@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        print(f"Signup failed: Username or email already taken for {user.username}")
        raise HTTPException(status_code=400, detail="Username or email already taken")

    # Hash the user's password before storing it
    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_password)

    # Add and commit the new user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Return the response
    response_data = {
        "message": "User created successfully",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email
        }
    }
    print(f"Signup successful: {response_data}")

    return response_data

# Login route with JWT implementation using JSON format and password verification
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    print(f"Received login request for username: {user.username}")

    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        print("Login failed: User not found")
        raise HTTPException(status_code=400, detail={"message":"Invalid username or password","status":False})
    
    if not verify_password(user.password, db_user.password):
        print("Login failed: Incorrect password")
        raise HTTPException(status_code=400, detail="Invalid username or password")

    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username, "role": "user"}, expires_delta=access_token_expires
    )

    # Prepare the response data
    response_data = {
        "status": True,
        "access_token": access_token,
         "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email,
            "role": "user"
        }
    }
    print(f"Login successful: {response_data}")

    return response_data

# Password reset route
@app.post("/reset-password")
def reset_password(reset: PasswordReset, db: Session = Depends(get_db)):
    # Fetch the user by username
    db_user = db.query(User).filter(User.username == reset.username).first()
    if not db_user:
        print("Password reset failed: User not found")
        raise HTTPException(status_code=404, detail="User not found")

    # Hash the new password
    new_hashed_password = hash_password(reset.new_password)
    
    # Update the user's password in the database
    db_user.password = new_hashed_password
    db.commit()

    # Return the response
    response_data = {
        "message": "Password reset successfully",
        "user": {
            "id": db_user.id,
            "username": db_user.username,
            "email": db_user.email
        }
    }
    print(f"Password reset successful: {response_data}")

    return response_data
# Logout route
@app.post("/logout")
def logout():
    # Notify the client to delete the JWT token
    response_data = {
        "message": "Logged out successfully. Please delete the JWT token from your client."
    }
    print(f"Logout successful: {response_data}")

    return response_data
# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
