from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Define your database URL
DATABASE_URL = "mysql+mysqlconnector://admin:Admin%40123@127.0.0.1:3306/e_com_db"

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a base class for your models
Base = declarative_base()

# Create a SessionLocal class to generate session instances
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
