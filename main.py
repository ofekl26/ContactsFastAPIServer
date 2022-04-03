from ast import excepthandler
from datetime import datetime, timedelta
import hashlib
from http.client import HTTPException
import bcrypt
from numpy import array, true_divide
from pydantic import BaseModel
import uvicorn
import json
from pymongo import MongoClient
from passlib.context import CryptContext 
from typing import Optional
from fastapi import Depends, FastAPI, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

# openssl rand -hex 32
SECRET_KEY = "ab7214536cf17304d4cfb2bd7ad15819b61861807f2be8b48f597effbc20302a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Req(BaseModel):
    title: str
    content: dict
    token: str = Depends(oauth2_scheme)

class User(BaseModel):
    username: str
    password: str
    deviceId: str

class UserInDB(User):
    hashed_password: str

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm='HS256')
    return encoded_jwt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

mongo = MongoClient(
    host=['localhost:27017'],
    serverSelectionTimeoutMS = 10000,
    document_class=dict,
    tz_aware=False,
    connect=True,
)

db = mongo.get_database('Vergo')

app = FastAPI()

@app.get("/")
async def read_root(token: str = Depends(oauth2_scheme)):
    return ["login","update","remove", jwt.decode(token,SECRET_KEY,algorithms='HS256')]

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Optional[str] = None):
    return {"item_id": item_id, "q": q}

@app.get("/contacts/")
async def send_contacts_list(token: str = Depends(oauth2_scheme)):
    user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    return dict(db.get_collection('Customers').find_one({'_username': user['username']}))['_contacts']

@app.post("/login/")
async def authorize_user(user: User) -> User:
    try:
        customer = list(db.get_collection('Customers').find({'_username':user.username}))
        #checking if customer is in db
        if customer == []:
            #adding new customer to the db and relating him to the device he logged in from
            db.get_collection('Customers').insert_one({'_username': user.username,'_password':bcrypt.hashpw(password = user.password, salt = bcrypt.gensalt()),'_deviceId':user.deviceId,'_contacts':[]})
            await authorize_device(user)
            token = jwt.encode(user.dict(),SECRET_KEY,algorithm='HS256')
            return {'access_token': token, 'token_type':'bearer'}
        else:
            if str(hashlib.sha256(user.username.encode('utf-8')).hexdigest()) == customer[0]['_password']:
                #verifying customers password and relating him to the device he logged in from
                await authorize_device(user)
                access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                access_token = create_access_token(data=user.dict(), expires_delta=access_token_expires)
                return {"access_token": access_token, "token_type": "bearer"}
            else:
                return False
    except Exception as err:
        return repr(err)

async def authorize_device(user):
    device = dict(db.get_collection('Devices').find_one({'_deviceId':user.deviceId}))
    #checking if the device id is in the db and if its not well add it
    if device is None:
        db.get_collection('Devices').insert_one({'_deviceId':user.deviceId})
        #added the device
    else:
        deviceLst = list(db.get_collection('Customers').find({'_deviceId':user.deviceId}))
        ok = False
        #checking if another user is using the same device
        #if someone else is related to this device well only relate our current user to the device
        #the user who used the device before will remain 'deviceless' in the db until hell log in from a device
        for x in deviceLst:
            if x['_username'] != user.username:
                db.get_collection('Customers').update_one({'_username': x['_username']},{'$set': {'_deviceId': ''}})
            else:
                ok = True
        if not ok:
            db.get_collection('Customers').update_one({'_username': user.username},{'$set': {'_deviceId': user.deviceId}})

@app.post("/contacts/")
async def update_contacts_request(req: Req, token: str = Depends(oauth2_scheme)) -> Req:
    try:
        user = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        contactsLst = dict(db.get_collection('Customers').find_one({'_username': user['username']}))['_contacts']
        update = False
        #request can either be an add request or a remove request
        #add request contains the following data:
        #[topic:"ADD",content:{contacts:[{'_cnum':'...','_cname':'...'},{...}]]
        if req.title == "ADD":
            for contact in req.content['contacts']:
                ok =False
                for _contact in contactsLst: 
                    #checking if contact already exists in db doc
                    #if it does we wont have to add it again
                    if _contact['_cnum'] == contact['_cnum'] and _contact['_cname'] == contact['_cname']:
                        ok = True
                        break
                if not ok:
                    contactsLst.append(contact)
                    update = True

        #remove request contains the following data:
        #[topic:"REMOVE",content:{'contacts':[{'_cname':'...'},{'_cname':'...'}],'username':'...'}]
        elif req.title == "REMOVE":
            for contact in req.content['contacts']:
                #checking if contact already exists in db doc
                #if it does we wont have to remove it
                for _contact in contactsLst: 
                    if _contact['_cname'] == contact['_cname']:
                        update = True
                        contactsLst.remove(_contact)
                        break

        if update:
                db.get_collection('Customers').update_one({'_username': user['username']},{'$set': {'_contacts': contactsLst}})
                return 'request has been fulfiled'
        
        else:
            return 'request is invalid'

    except Exception as err:
        return repr(err)

if __name__ == "__main__":
    uvicorn.run(app,
      host="localhost",
      port=8556,
    #   reload = True,
      ssl_keyfile='C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\server.key',
      ssl_certfile='C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\server.crt')