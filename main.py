from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List
# import asyncio
import os
import secrets
# import mimetypes
import uuid
# from bson import ObjectId
import aiofiles
# import smtplib
from email.mime.text import MIMEText

# Configuration
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_DIR = "./uploads"
MONGO_URI = "mongodb+srv://dasarilikhitadevi:1VCaprW0kLfM8Xfa@cluster0.vywnuwf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "file_sharing_db"

app = FastAPI()
@app.get("/")
def read_root():
    return {"message": "Hello, this is Likhita!"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MongoDB Client
# client = AsyncIOMotorClient(MONGO_URI)
# db = client[DB_NAME]
client = AsyncIOMotorClient(MONGO_URI)
db = client["file_sharing_db"]


# Models
class User(BaseModel):
    email: EmailStr
    password: str
    user_type: str  # 'ops' or 'client'

class UserInDB(User):
    hashed_password: str
    is_verified: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class FileMetadata(BaseModel):
    filename: str
    file_id: str
    uploaded_by: str
    upload_time: datetime
    secure_url: str

# Helper Functions
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_type: str = payload.get("user_type")
        if email is None or user_type is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = await db.users.find_one({"email": email})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def send_verification_email(email: str, verification_token: str):
    # Mock email sending (replace with actual SMTP settings)
    msg = MIMEText(f"Verify your email: http://localhost:8000/verify-email?token={verification_token}")
    msg['Subject'] = 'Email Verification'
    msg['From'] = 'no-reply@filesharing.com'
    msg['To'] = email
    # Configure SMTP server here for production
    # with smtplib.SMTP('smtp.gmail.com', 587) as server:
    #     server.starttls()
    #     server.login("your_email", "your_password")
    #     server.send_message(msg)
    print(f"Verification email sent to {email} with token {verification_token}")

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# APIs
@app.post("/signup", response_model=Token)
async def signup(user: User):
    print("Received signup request:", user.dict())  # Add this

    if user.user_type not in ["ops", "client"]:
        raise HTTPException(status_code=400, detail="Invalid user type")

    try:
        existing_user = await db.users.find_one({"email": user.email})
        print("Existing user check:", existing_user)
    except Exception as e:
        print("MongoDB error:", str(e))  # <-- PRINTS error details
        raise HTTPException(status_code=500, detail="Database connection failed")

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    try:
        verification_token = secrets.token_urlsafe(32)
        hashed_password = pwd_context.hash(user.password)

        user_dict = {
            "email": user.email,
            "hashed_password": hashed_password,
            "user_type": user.user_type,
            "is_verified": False,
            "verification_token": verification_token
        }

        await db.users.insert_one(user_dict)
        await send_verification_email(user.email, verification_token)

        access_token = create_access_token(data={"sub": user.email, "user_type": user.user_type})
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        print("Signup error:", str(e))
        raise HTTPException(status_code=500, detail="Signup failed")

@app.get("/verify-email")
async def verify_email(token: str):
    user = await db.users.find_one({"verification_token": token})
    users = await db.users.find().to_list(length=100)
    for u in users:
        print(u.get("email"), ":", u.get("verification_token"))

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    await db.users.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}, "$unset": {"verification_token": ""}})
    return {"message": "Email verified successfully"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user["is_verified"]:
        raise HTTPException(status_code=401, detail="Email not verified")
    access_token = create_access_token(data={"sub": user["email"], "user_type": user["user_type"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if current_user["user_type"] != "ops":
        raise HTTPException(status_code=403, detail="Only ops users can upload files")
    
    allowed_extensions = {".pptx", ".docx", ".xlsx"}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Invalid file type. Only pptx, docx, xlsx allowed")
    
    file_id = str(uuid.uuid4())
    secure_url = f"/download-file/{file_id}"
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")
    
    async with aiofiles.open(file_path, 'wb') as out_file:
        content = await file.read()
        await out_file.write(content)
    
    file_metadata = {
        "filename": file.filename,
        "file_id": file_id,
        "uploaded_by": current_user["email"],
        "upload_time": datetime.utcnow(),
        "secure_url": secure_url
    }
    await db.files.insert_one(file_metadata)
    return {"message": "File uploaded successfully", "secure_url": secure_url}

@app.get("/list-files", response_model=List[FileMetadata])
async def list_files(current_user: dict = Depends(get_current_user)):
    if current_user["user_type"] != "client":
        raise HTTPException(status_code=403, detail="Only client users can list files")
    files = await db.files.find().to_list(length=100)
    return files

@app.get("/download-file/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["user_type"] != "client":
        raise HTTPException(status_code=403, detail="Only client users can download files")
    files = await db.files.find().to_list(length=100)
    for u in files:
        print( "File :", u.get("file_id"))
    file_metadata = await db.files.find_one({"file_id": file_id})
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}{os.path.splitext(file_metadata['filename'])[1]}")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")
    
    # In production, serve file securely or return a pre-signed URL (e.g., AWS S3)
    return {
        "download-link": file_metadata["secure_url"],
        "message": "success"
    }

# Test Cases (Using pytest)
"""
import pytest
from fastapi.testclient import TestClient
from .main import app, db

client = TestClient(app)

@pytest.fixture
async def setup_db():
    await db.users.delete_many({})
    await db.files.delete_many({})

@pytest.mark.asyncio
async def test_signup(setup_db):
    response = client.post("/signup", json={"email": "test@client.com", "password": "password123", "user_type": "client"})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_login(setup_db):
    client.post("/signup", json={"email": "test@ops.com", "password": "password123", "user_type": "ops"})
    await db.users.update_one({"email": "test@ops.com"}, {"$set": {"is_verified": True}})
    response = client.post("/login", data={"username": "test@ops.com", "password": "password123"})
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_upload_file(setup_db):
    client.post("/signup", json={"email": "test@ops.com", "password": "password123", "user_type": "ops"})
    await db.users.update_one({"email": "test@ops.com"}, {"$set": {"is_verified": True}})
    token = client.post("/login", data={"username": "test@ops.com", "password": "password123"}).json()["access_token"]
    with open("test.docx", "wb") as f:
        f.write(b"Test content")
    with open("test.docx", "rb") as f:
        response = client.post("/upload-file", files={"file": f}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert "secure_url" in response.json()

@pytest.mark.asyncio
async def test_download_file(setup_db):
    client.post("/signup", json={"email": "test@client.com", "password": "password123", "user_type": "client"})
    await db.users.update_one({"email": "test@client.com"}, {"$set": {"is_verified": True}})
    token = client.post("/login", data={"username": "test@client.com", "password": "password123"}).json()["access_token"]
    response = client.get("/download-file/invalid_id", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
"""

# Deployment Plan
"""
1. **Infrastructure**:
   - Use Docker to containerize the FastAPI application.
   - Deploy on AWS ECS or Kubernetes for scalability.
   - Use MongoDB Atlas for managed database hosting.
   - Store files in AWS S3 with pre-signed URLs for secure downloads.
   - Use AWS CloudFront as a CDN for file delivery.

2. **CI/CD**:
   - Set up a GitHub Actions pipeline for automated testing and deployment.
   - Run pytest tests on every push to the main branch.
   - Deploy to staging environment for testing, then promote to production.

3. **Security**:
   - Use AWS WAF to protect against common web exploits.
   - Implement rate limiting using FastAPI middleware.
   - Enable HTTPS with Let's Encrypt or AWS ACM.
   - Regularly rotate SECRET_KEY and store it in AWS Secrets Manager.

4. **Monitoring and Logging**:
   - Use AWS CloudWatch for application logs and metrics.
   - Set up alerts for high error rates or latency.
   - Implement distributed tracing with AWS X-Ray.

5. **Scalability**:
   - Use AWS Auto Scaling to handle traffic spikes.
   - Implement MongoDB sharding for database scalability.
   - Cache frequently accessed files in CloudFront.
"""
# from fastapi import FastAPI

# app = FastAPI()

# @app.get("/")
# def read_root():
#     return {"message": "Hello , This is Likhita."}
