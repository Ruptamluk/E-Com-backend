from sqlalchemy import create_engine, Column, Integer, String, DateTime , Index
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

    # Add a relationship if needed
    # otp = relationship("OTP", back_populates="user")

class OTP(Base):
    __tablename__ = 'otps'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False)
    otp = Column(String(6), nullable=False)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)


class ICON(Base):
    __tablename__ = 'icons'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    icon_url = Column(String(255), nullable=False)
    


    # If needed, add a relationship back to the User model
    # user_id = Column(Integer, ForeignKey('users.id'))
    # user = relationship("User", back_populates="otp")
