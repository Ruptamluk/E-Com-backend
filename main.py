from fastapi import FastAPI, HTTPException, Depends, Query, Body
from sqlalchemy.orm import sessionmaker, Session 
from sqlalchemy import text
from datetime import datetime, timedelta
import bcrypt
import jwt
import uuid
import time
from pydantic import BaseModel, EmailStr
from email_Verification import send_email, generate_otp
from models import User, OTP, Icon  # Added ICON model
from schemas import UserCreate, UserLogin, IconCreate,IconResponse , ForgotPassword, ChangePasswordRequest  # Added GetIcon schema
from database import engine, Base, get_db
from typing import Dict

# Temporary storage for verified emails
verified_emails: Dict[str, str] = {}

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

# # Function to retrieve an icon by id
# def get_icon(db: Session, icon_id: int) -> GetIcon:
#     icon = db.query(ICON).filter(ICON.id == icon_id).first()
#     if not icon:
#         raise HTTPException(status_code=404, detail="Icon not found")
#     return GetIcon(id=icon.id, name=icon.name, icon_url=icon.icon_url)

# # API route to retrieve an icon by id
# @app.get("/icons/{icon_id}", response_model=GetIcon)
# def read_icon(icon_id: int, db: Session = Depends(get_db)):
#     return get_icon(db=db, icon_id=icon_id)
# @app.post("/icons/")
# def create_icon(icon: IconCreate, db: Session = Depends(get_db)):
#     # Create an icon instance
#     db_icon = ICON(name=icon.name, icon_url=icon.icon_url)

#     # Add the icon to the session
#     db.add(db_icon)
#     db.commit()
#     db.refresh(db_icon)  # Refresh to get the ID of the newly inserted record

#     return {
#         "message": "Icon created successfully",
#         "icon": {
#             "id": db_icon.id,
#             "name": db_icon.name,
#             "icon_url": db_icon.icon_url
#         }
#     }


# # Function to retrieve an icon by id
# def get_icon(db: Session, icon_id: int) -> GetIcon:
#     icon = db.query(ICON).filter(ICON.id == icon_id).first()
#     if not icon:
#         raise HTTPException(status_code=404, detail="Icon not found")
#     return GetIcon(id=icon.id, name=icon.name, icon_url=icon.icon_url)


# # API route to retrieve an icon by id
# @app.get("/icons/{icon_id}", response_model=GetIcon)
# def read_icon(icon_id: int, db: Session = Depends(get_db)):
#     return get_icon(db=db, icon_id=icon_id)
# Function to create the 'icons' table using raw SQL
def create_icon_table(db: Session):
    create_table_query = """
    CREATE TABLE IF NOT EXISTS icons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        icon_url VARCHAR(255) NOT NULL
    );
    """
    db.execute(text(create_table_query))
    db.commit()

# Function to manually insert icons into the 'icons' table
def insert_icon_manually(db):
    insert_data_query = """
    INSERT INTO icons (name, icon_url)
    VALUES
        ('Medicine', 'https://img.icons8.com/?size=100&id=108787&format=png&color=000000'),
        ('Fruits', 'https://img.icons8.com/?size=100&id=jgkOOM1KTHRc&format=png&color=000000'),
        ('Vegetable', 'https://img.icons8.com/?size=100&id=cpa3RyNsYJkU&format=png&color=000000'),
        ('Cosmetics', 'https://img.icons8.com/?size=100&id=UJikDF3wj2jk&format=png&color=000000'),
        ('Grocery', 'https://img.icons8.com/?size=100&id=enZOTH5kGrxd&format=png&color=000000');
    """
    
    try:
        db.execute(text(insert_data_query))
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error inserting data: {str(e)}")
# Route to create the 'icons' table
@app.post("/create-icons-table/")
def create_table(db: Session = Depends(get_db)):
    try:
        create_icon_table(db)
        return {"message": "Icons table created successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating table: {e}")

# Route to manually insert icons into the 'icons' table
@app.post("/insert-icons-manually/")
def insert_icons(db: Session = Depends(get_db)):
    try:
        insert_icon_manually(db)
        return {"message": "Icons inserted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inserting data: {e}")


# Function to retrieve an icon by id
# def get_icon(db: Session, icon_id: int) -> GetIcon:
#     icon = db.query(ICON).filter(ICON.id == icon_id).first()
#     if not icon:
#         raise HTTPException(status_code=404, detail="Icon not found")
#     return GetIcon(id=icon.id, name=icon.name, icon_url=icon.icon_url)


# # API route to retrieve an icon by id
# @app.get("/icons/{icon_id}", response_model=GetIcon)
# def read_icon(icon_id: int, db: Session = Depends(get_db)):
#     return get_icon(db=db, icon_id=icon_id)

@app.get("/get-icon/{icon_id}", response_model=IconResponse)
def get_icon(icon_id: int, db: Session = Depends(get_db)):
    icon = db.query(Icon).filter(Icon.id == icon_id).first()
    if icon is None:
        raise HTTPException(status_code=404, detail="Icon not found")
    return icon

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
verified_email_cache = {}

@app.post("/verify-otp/")
def verify_otp(email: EmailStr = Body(...), otp: str = Body(...), db: Session = Depends(get_db)):
    otp_record = db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Check if OTP has expired
    if otp_record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP has expired")

    # Store the verified email in temporary in-memory storage
    verified_email_cache[email] = True
    
    # Remove OTP after successful verification (optional)
    db.delete(otp_record)
    db.commit()
    
    return {"message": "OTP verified successfully. You can now reset your password."}

# Change password after OTP verification (Step 3: Change the password)
@app.post("/change-password/")
def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    # Retrieve the email from the in-memory cache
    email = None
    for cached_email in verified_email_cache:
        if verified_email_cache[cached_email]:
            email = cached_email
            break

    if not email:
        raise HTTPException(status_code=400, detail="No verified email found. Please verify OTP first.")

    # Find the user
    db_user = db.query(User).filter(User.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update the user's password
    db_user.password = hash_password(request.new_password)
    db.commit()

    # Remove email from cache after successful password reset
    del verified_email_cache[email]

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
