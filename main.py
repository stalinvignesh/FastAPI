import hashlib
import uuid
from fastapi import FastAPI, HTTPException, Body, Depends, Request, Header
from fastapi import UploadFile, File, Form , Query
from fastapi.params import Query
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta , date
import random
from typing import List, Dict
import gridfs
from bson import ObjectId, errors as bson_errors
import io
import websockets
import websocket

from starlette.responses import JSONResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  #Need to set for PROD
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client["weceleb"]
#fs = gridfs.GridFS(db)
fs = AsyncIOMotorGridFSBucket(db)

SECRET_KEY = "SECRET_KEY"
RESET_KEY = "RESET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
RESET_TOKEN_EXPIRE_MINUTES = 5

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
oauth2_scheme_reset = OAuth2PasswordBearer(tokenUrl="/reset")

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    message : str

class ResetToken(BaseModel):
    reset_token: str
    token_type: str = "bearer"
    message : str


class RefreshToken(BaseModel):
    refresh_token: str

class ResetPin(BaseModel):
    email : str
    message : str

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
    expire = datetime.now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_reset_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, RESET_KEY, algorithm=ALGORITHM)

@app.post("/send_otp")
async def send_otp(request: OTPRequest):
    otp = f"{random.randint(1000, 9999)}"
    #otp_store[request.phone_number] = otp
    otp = '1234'
    # Here you should integrate with SMS provider to send the OTP
    #print(f"OTP for {request.phone_number} is {otp}")  # For demo only
    return {"message": "OTP sent"}

#@app.post("/verify_otp")
@app.post("/token", response_model=Token)
async def token(request: OTPVerifyRequest):
    #expected_otp = otp_store.get(request.phone_number)
    pin = await db["user_data"].find_one({"mobile":request.phone_number},{ "_id" : 0 , "pin" :1 })
    expected_otp = pwd_context.verify(request.otp,pin["pin"])
    if not expected_otp:
        raise HTTPException(status_code=400, detail="Invalid PIN/OTP")
    access_token = create_access_token(data={"sub": request.phone_number}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = str(uuid.uuid4())
    await db["refresh_tokens"].insert_one({
        "token": refresh_token,
        "mobile": request.phone_number,
        "expires": datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    })
    return {"access_token": access_token, "refresh_token": refresh_token , "message" : "success"}

@app.post("/reset",response_model=ResetToken)
async def reset(request: OTPVerifyRequest ):
    reset_token = create_reset_token(data={"sub": request.phone_number}, expires_delta=timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES))
    await db["refresh_tokens"].insert_one({
        "token": reset_token,
        "mobile": request.phone_number,
        "expires": datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    })
    return {"reset_token": reset_token,"message" : "success"}



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
        raise HTTPException(status_code=403, detail="Could not validate credentials or expired.")

async def get_current_reset_user(authorization: str = Header(...)):
    token = authorization.split(" ")[1] # Bearer <token>
    try:
        payload = jwt.decode(token, RESET_KEY, algorithms=[ALGORITHM])
        phone_number = payload.get("sub")
        if phone_number is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return phone_number
    except JWTError:
        raise HTTPException(status_code=403, detail="Could not validate credentials or expired.")

async def get_current_user_websocket(token: str):
    """Modified version for WebSocket token validation"""
    credentials_exception = WebSocketDisconnect(code=1008, reason="Invalid token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone_number: str = payload.get("sub")
        if phone_number is None:
            raise credentials_exception
        return phone_number
    except JWTError:
        raise credentials_exception

async def verify_api_key(authorization: str = Header(...)):
    if authorization != f"Bearer {SECRET_KEY}":
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

@app.post("/reset_pin",response_model=ResetPin)
async def reset_pin(request: OTPVerifyRequest , _: str = Depends(get_current_reset_user)):
    pin = request.otp
    pin_hash = pwd_context.hash(pin)
    updated = await db["user_data"].update_one({"mobile":request.phone_number},{"$set":{"pin":pin_hash ,
                                                                                        "is_pin_permanent" : False}})
    email = await db["user_data"].find_one({"mobile":request.phone_number},{ "_id" : 0 , "email" :1 })
    if updated.modified_count != 1 :
        return { "email" : "Error" ,"message": "Error updating DB" }
    return {"email" : email["email"] ,"message": "Reset Success" }

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

@app.delete("/delete_refresh/{phone_number}")
async def delete_refresh(phone_number: str):
    await db["refresh_tokens"].delete_many({"mobile":phone_number})
    return {"message" : "Deleted All Refresh"}

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

@app.post("/upload_photos")
async def upload_photos(
    user_id: int = Form(...),
    marriage_code : str = Form(...),
    files: list[UploadFile] = File(...),
    _: str = Depends(get_current_user)
):
    file_ids = []
    for file in files:
        content = await file.read()
        file_id = await fs.upload_from_stream(file.filename,content)
        file_ids.append(file_id)
    today_date = str(datetime.now())
    await db["marriage_photos"].insert_one({"user_id": user_id, "photo_ids": file_ids,
                                            "marriage_code" : marriage_code ,"uploaded_date": today_date})
    return {"uploaded": [str(fid) for fid in file_ids]}

@app.get("/get_photo/{file_id}")
async def get_photo(file_id: str, _: str = Depends(get_current_user)):
    try:
        oid = ObjectId(file_id)
    except bson_errors.InvalidId:
        raise HTTPException(status_code=400, detail="Invalid file_id")
    grid_out = await fs.open_download_stream(oid)
    contents = await grid_out.read()
    return StreamingResponse(io.BytesIO(contents), media_type="image/jpeg")

@app.get("/get_photos/user/{user_id}")
async def get_user_photos(user_id: int, _: str = Depends(get_current_user)):
    cursor =  db["marriage_photos"].find({"user_id": user_id})
    results = []
    if cursor.alive:
        async for doc in cursor:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
            if "photo_ids" in doc:
                doc["photo_ids"] = [str(pid) for pid in doc["photo_ids"]]
            results.append(doc)
    return results

@app.get("/get_photos/marriage/{marriage_code}")
async def get_marriage_photos(marriage_code: str, _: str = Depends(get_current_user)):
    cursor = db["marriage_photos"].find({"marriage_code": marriage_code})
    results = []
    if cursor.alive:
        async for doc in cursor:
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])  # Convert ObjectId to string
            if "photo_ids" in doc:
                doc["photo_ids"] = [str(pid) for pid in doc["photo_ids"]]
            results.append(doc)
    return results
    #if not record: #this is for find_one
    #    return {"photo_ids": []}
    #return {"photo_ids": [str(fid) for fid in record["photo_ids"]]}

@app.post("/delete_photo/{photo_id}")
async def delete_photo(
    photo_id: str ,
    user_id: int = Form(...),
    marriage_code : str =  Form(...),
    _: str = Depends(get_current_user)
):
    try:
        # Delete the file from GridFS
        await fs.delete(ObjectId(photo_id))
        #print(f"user is {user_id} and marriage_code is {marriage_code}")

        # Also remove its reference from photos collection
        await db["marriage_photos"].update_many(
            {"user_id": int(user_id),"marriage_code" : marriage_code},
            {"$pull": {"photo_ids": ObjectId(photo_id)}}
        )

        #Delete the document if photo_ids is empty
        cursor = db["marriage_photos"].find({"user_id": int(user_id),"marriage_code" : marriage_code})
        if cursor.alive:
            async for record in cursor:
                if not record["photo_ids"]:
                    await db["marriage_photos"].delete_one({"_id" : ObjectId(record["_id"])})

        return {"status": "success", "message": f"Photo {photo_id} deleted."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.delete("/delete_photos/")
async def delete_photos(
    user_id: str = Body(...),
    photo_ids: list[str] = Body(...),
    _: str = Depends(get_current_user)
):
    try:
        for pid in photo_ids:
            await fs.delete(ObjectId(pid))

        # Remove all from user doc
        await db["marriage_photos"].update_one(
            {"user_id": user_id},
            {"$pull": {"photo_ids": {"$in": [ObjectId(pid) for pid in photo_ids]}}}
        )

        return {"status": "success", "deleted": photo_ids}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

class ConnectionManager:
    def __init__(self):
        self.rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, marriage_code: str, websocket: WebSocket):
        await websocket.accept()
        if marriage_code not in self.rooms:
            self.rooms[marriage_code] = []
        self.rooms[marriage_code].append(websocket)

    def disconnect(self, marriage_code: str, websocket: WebSocket):
        self.rooms[marriage_code].remove(websocket)
        if not self.rooms[marriage_code]:
            del self.rooms[marriage_code]

    async def broadcast(self, marriage_code: str, message: str):
        if marriage_code in self.rooms:
            for connection in self.rooms[marriage_code]:
                await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/live/{marriage_code}")
async def websocket_endpoint(websocket: WebSocket, marriage_code: str, token: str , user : int,nick_name : str):
    # Do JWT auth just like your normal Depends:
    user_ph = await get_current_user_websocket(token)

    await manager.connect(marriage_code, websocket)
    print(marriage_code,token,user,nick_name)
    try:
        while True:
            data = await websocket.receive_text()
            timestamp = str(datetime.now().replace(microsecond=0))
            doc = {
                "marriage_code": marriage_code,
                "user_id": int(user),
                "nick_name": nick_name,
                "comment" : data,
                "timestamp": timestamp
            }
            await db["video_comments"].insert_one(doc)
            await manager.broadcast(marriage_code, f"{nick_name}: {data} {timestamp}")
    except WebSocketDisconnect:
        manager.disconnect(marriage_code, websocket)

@app.get("/comments/{marriage_code}")
async def get_history(marriage_code: str, _: str = Depends(get_current_user)):
    messages = []
    cursor = db["video_comments"].find({"marriage_code": marriage_code}).sort("timestamp", -1).limit(50)
    async for doc in cursor:
        messages.append(f"{doc['nick_name']}: {doc['comment']} {doc['timestamp']}")
    return messages[::-1]

@app.delete("/delete_comment")
async def delete_comment(user_id: int = Body(...),
    comment : str = Body(...),
    marriage_code : str = Body(...),
    timestamp: str = Body(...),
    _: str = Depends(get_current_user)
):
    print(user_id,marriage_code,comment,timestamp)
    await db["video_comments"].delete_one({"user_id": int(user_id),"marriage_code" : marriage_code,"comment":comment,
                                     "timestamp":timestamp})
    return {"status": "deleted"}