from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session

from models import User
from schemas import UserCreate, UserLogin
from database import engine, Base, get_db

# Initialize FastAPI app
app = FastAPI()

# Create the database tables
Base.metadata.create_all(bind=engine)

# Signup route
@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already taken")

    # Create a new User instance
    new_user = User(username=user.username, email=user.email, password=user.password)

    # Add and commit the new user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully", "user": {"id": new_user.id, "username": new_user.username, "email": new_user.email}}

# Login route
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    if user.password != db_user.password:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    return {"message": "Login successful", "user": {"id": db_user.id, "username": db_user.username, "email": db_user.email}}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
