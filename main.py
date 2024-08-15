from fastapi import FastAPI, HTTPException, Depends, Form, Query ,Body

from datetime import datetime, timedelta
import bcrypt
import jwt
import uuid
import time
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, EmailStr
from email_Verification import send_email, generate_otp  # Import new function

from models import User , OTP
from schemas import UserCreate, UserLogin, PasswordReset, ForgotPassword , ChangePasswordRequest
from database import engine, Base, get_db
from sqlalchemy.orm import Session
# Initialize FastAPI app
app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)

# Secret key to encode JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# In-memory storage for OTPs and tokens (for simplicity)
otp_storage = {}
tokens = {}

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
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

# Generate a unique token
def generate_token(email: str) -> str:
    token = str(uuid.uuid4())
    tokens[token] = {"email": email, "timestamp": time.time()}
    return token

# Validate the token
def validate_token(token: str) -> str:
    if token not in tokens:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    token_data = tokens[token]
    if time.time() - token_data["timestamp"] > 900:  # 900 seconds = 15 minutes
        del tokens[token]
        raise HTTPException(status_code=400, detail="Token expired")
    return token_data["email"]

# Signup route
@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already taken")

    hashed_password = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User created successfully",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email
        }
    }

# Login route with JWT implementation using JSON format and password verification
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username, "role": "user"}, expires_delta=access_token_expires
    )

    return {
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

# Forgot Password route (Step 1: Request password reset)
# @app.post("/forgot-password")
# def forgot_password(forgot: ForgotPassword, db: Session = Depends(get_db)):
#     # Check if the user exists
#     db_user = db.query(User).filter(User.username == forgot.username, User.email == forgot.email).first()
#     if not db_user:
#         raise HTTPException(status_code=404, detail="User not found")

#     # Generate OTP and its expiration time
#     otp = generate_otp()
#     expires_at = datetime.utcnow() + timedelta(minutes=15)  # OTP valid for 15 minutes

#     # Store OTP in the database
#     otp_entry = OTP(email=forgot.email, otp=otp, created_at=datetime.utcnow(), expires_at=expires_at)
#     db.add(otp_entry)
#     db.commit()

#     # Create OTP email content
#     subject = "Password Reset OTP"
#     body = f"Your OTP for password reset is: {otp}"

#     # Send the OTP via email
#     send_email(forgot.email, subject, body)

#     return {"message": "OTP sent to your email. Please check your inbox."}
@app.post("/forgot-password")
def forgot_password(forgot: ForgotPassword, db: Session = Depends(get_db)):
    # Check if the user exists
    db_user = db.query(User).filter(User.username == forgot.username, User.email == forgot.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate OTP and its expiration time
    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=15)  # OTP valid for 15 minutes

    # Create OTP entry and store it in the database
    otp_entry = OTP(email=forgot.email, otp=otp, created_at=datetime.utcnow(), expires_at=expires_at)
    try:
        db.add(otp_entry)
        db.commit()
    except Exception as e:
        db.rollback()  # Rollback in case of error
        raise HTTPException(status_code=500, detail=f"Error storing OTP: {e}")

    # Create OTP email content
    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}"

    # Send the OTP via email
    try:
        send_email(forgot.email, subject, body)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending email: {e}")

    return {"message": "OTP sent to your email. Please check your inbox."}


# OTP Verification route (Step 2: Verify the OTP)
@app.post("/verify-otp/")
def verify_otp(email: EmailStr = Body(...), otp: str = Body(...)):
    db = SessionLocal()
    try:
        otp_record = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
        if not otp_record:
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        # Check if OTP has expired
        if otp_record.expires_at < datetime.utcnow():
            raise HTTPException(status_code=400, detail="OTP has expired")

        # Remove OTP after successful verification (optional)
        # db.delete(otp_record)
        db.commit()
        
        return {"message": "OTP verified successfully. You can now reset your password."}
    finally:
        db.close()

# Change password after OTP verification (Step 3: Change the password)
@app.post("/change-password/")
def change_password(request: ChangePasswordRequest = Body(...), db: Session = Depends(get_db)):
    # Validate the OTP
    otp_record = db.query(OTP).filter(OTP.email == request.email, OTP.otp == request.otp).first()
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Check if OTP has expired
    if otp_record.expires_at < datetime.utcnow():
        db.delete(otp_record)  # Optionally remove expired OTP from the database
        db.commit()
        raise HTTPException(status_code=400, detail="OTP has expired")

    # Find the user
    db_user = db.query(User).filter(User.email == request.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update the user's password
    db_user.password = hash_password(request.new_password)
    db.commit()

    # Remove OTP after successful password reset
    db.delete(otp_record)
    db.commit()

    return {"message": "Password changed successfully."}
    

# Token verification route (Newly added)
@app.get("/verify-token/")
def verify_token(token: str = Query(...)):
    try:
        email = validate_token(token)
    except HTTPException as e:
        return {"message": e.detail, "status": False}

    return {"message": "Token verified successfully.", "status": True, "email": email}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
