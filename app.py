from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import mysql.connector

# Define your database URL
DATABASE_URL = DATABASE_URL = "mysql+mysqlconnector://admin:Admin%40123@127.0.0.1:3306/e_com_db"

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a base class for your models
Base = declarative_base()

# Create a SessionLocal class to generate session instances
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# FastAPI app instance
app = FastAPI()

# Define a Pydantic model for incoming signup requests
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

# Define the User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password = Column(String(100), nullable=False)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create the database tables
Base.metadata.create_all(bind=engine)

# Signup route
@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the username or email already exists
    existing_user = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already taken")

    # Create a new User instance
    new_user = User(username=user.username, email=user.email, password=user.password)

    # Add and commit the new user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully", "user": {"id": new_user.id, "username": new_user.username, "email": new_user.email}}


# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
