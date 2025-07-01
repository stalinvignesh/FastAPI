import uuid
from fastapi import FastAPI, HTTPException, Body, Depends, Request, Header
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import random
from typing import List

from starlette.responses import JSONResponse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client["weceleb"]

SECRET_KEY = "SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    message : str


class RefreshToken(BaseModel):
    refresh_token: str


# Temporary store for OTPs (in-memory for demo; use DB or Redis in prod)
otp_store = {}

class OTPRequest(BaseModel):
    phone_number: str

class OTPVerifyRequest(BaseModel):
    phone_number: str
    otp: str

class UpdatePayload(BaseModel):
    query: dict
    data: dict

class FindPayload(BaseModel):
    query : dict
    require : dict

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/send_otp")
async def send_otp(request: OTPRequest):
    otp = f"{random.randint(1000, 9999)}"
    #otp_store[request.phone_number] = otp
    otp = '1234'
    # Here you should integrate with SMS provider to send the OTP
    print(f"OTP for {request.phone_number} is {otp}")  # For demo only
    return {"message": "OTP sent"}

#@app.post("/verify_otp")
@app.post("/token", response_model=Token)
async def token(request: OTPVerifyRequest):
    #expected_otp = otp_store.get(request.phone_number)
    expected_otp = '1234'
    if expected_otp != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    access_token = create_access_token(data={"sub": request.phone_number}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = str(uuid.uuid4())
    await db["refresh_tokens"].insert_one({
        "token": refresh_token,
        "mobile": request.phone_number,
        "expires": datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    })
    return {"access_token": access_token, "refresh_token": refresh_token , "message" : "success"}

# Dependency to get current user from token
async def get_current_user(authorization: str = Header(...)):
    token = authorization.split(" ")[1]  # Bearer <token>
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone_number = payload.get("sub")
        if phone_number is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return phone_number
    except JWTError:
        raise HTTPException(status_code=403, detail="Could not validate credentials")

async def verify_api_key(authorization: str = Header(...)):
    if authorization != f"Bearer {SECRET_KEY}":
        raise HTTPException(status_code=403, detail="Invalid or missing API key")


@app.post("/refresh", response_model=Token)
async def refresh_token(data : RefreshToken):
    refresh_token = data.refresh_token
    entry = await db["refresh_tokens"].find_one({"token": refresh_token})
    if not entry:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if entry["expires"] < datetime.now():
        await db["refresh_tokens"].delete_one({"token": refresh_token})
        raise HTTPException(status_code=401, detail="Refresh token expired")
    phone_number = entry["mobile"]
    access_token = create_access_token(data={"sub": phone_number}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "refresh_token": refresh_token , "message" : "success"}

@app.post("/logout")
async def logout(data : RefreshToken):
    refresh_token = data.refresh_token
    await db["refresh_tokens"].delete_one({"token": refresh_token})
    return {"message": "Logged out"}

@app.get("/secure_data")
async def secure_data(user: str = Depends(get_current_user)):
    return {"message": f"Hello {user}, this is secured data."}

@app.post("/insert/{collection}/")
async def create_doc(collection: str, data: dict = Body(...), _: str = Depends(get_current_user)):
    result = await db[collection].insert_one(data)
    return {"id": str(result.inserted_id)}

@app.get("/{collection}/by_field/{field}/{value}")
async def get_by_field(collection: str, field: str, value: str, _: str = Depends(get_current_user)):
    query = {field: value}
    doc = await db[collection].find_one(query)
    if not doc:
        #raise HTTPException(status_code=404, detail="Not found")
        return {"message" : "new_user"}
    doc["id"] = str(doc["_id"])
    doc.pop("_id", None)
    return doc

@app.post("/find/{collection}")
async def get_by_find(collection: str, payload: FindPayload,_: str = Depends(get_current_user)):
    cursor = db[collection].find(payload.query , payload.require)
    results = []
    #if not cursor.alive:
        #raise HTTPException(status_code=404, detail="Not found")
    if cursor.alive:
        async for doc in cursor:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
            results.append(doc)
    return results

@app.post("/find_one/{collection}")
async def get_by_find_one(collection: str, payload: FindPayload,_: str = Depends(get_current_user)):
    doc = await db[collection].find_one(payload.query,payload.require)
    #if not doc:
    #    raise HTTPException(status_code=404, detail="Not found")
    if doc:
        if "_id" in doc:
            doc["id"] = str(doc["_id"])
            doc.pop("_id", None)
    return doc

@app.put("/update/{collection}")
async def update_by_fields(collection: str, payload: UpdatePayload, _: str = Depends(get_current_user)):
    result = await db[collection].update_one(payload.query, {"$set": payload.data})
    #if result.modified_count == 0:
    #    raise HTTPException(status_code=404, detail="Update failed")
    return {"modified_count": result.modified_count}

@app.delete("/delete/{collection}")
async def delete_by_field(collection: str, query: dict = Body(...), _: str = Depends(get_current_user)):
    result = await db[collection].delete_one(query)
    #if result.deleted_count == 0:
    #    raise HTTPException(status_code=404, detail="Delete failed")
    return {"deleted_count" : result.deleted_count}
'''
#Need to remove below route
@app.get("/{collection}/")
async def get_all_docs(collection: str, _: str = Depends(get_current_user)):
    cursor = db[collection].find()
    docs = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        doc.pop("_id", None)
        docs.append(doc)
    return docs
'''
@app.post("/aggregate/{collection}")
async def aggregate_docs(collection: str,pipeline: List[dict] = Body(...),
    _: str = Depends(get_current_user) ):
    try:
        cursor = db[collection].aggregate(pipeline)
        result = []
        async for doc in cursor:
            if doc:
                if "_id" in doc:
                    doc["id"] = str(doc["_id"])
                    doc.pop("_id", None)
                result.append(doc)
        return result
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

