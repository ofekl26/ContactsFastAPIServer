from lib2to3.pgen2 import token
from mimetypes import init
from urllib import request
import bcrypt
import hashlib
from pydantic import BaseModel
from pydantic import BaseModel
import requests
from jose import jwt


class User(BaseModel):
    deviceId:str
    username: str
    password:str

class Req(BaseModel):
    title: str
    content: dict

u1 = User(username = 'ctest3',password = 'Aa123',deviceId='2fb1fe6d200ff1a1')
r1 = Req(title = "ADD", content={'contacts':[{'_cnum':'554631','_cname':'test'}]})
r2 =  Req(title = "REMOVE", content={'username':'ctest','contacts':[{'_cname':'test3'}]})

# print(u1)
# r = requests.post("https://172.20.10.4:8556/login/", json={'username': 'ctest3','password': 'Aa123','deviceId': '1'}, verify="C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\cert.pem")
r1 = requests.get("https://172.20.10.4:8556/contacts/", headers={"Authorization": "Bearer "+r.json()['access_token']},verify="C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\cert.pem")
# r1 = requests.get("https://localhost:8556/", headers={"Authorization": "Bearer "+r.json()['access_token']},verify="C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\rootCA.pem")
# r = requests.post("https://localhost:8556/contacts/", json=dict(r1), headers={"Authorization": "Bearer "+r.json()['access_token']}, verify="C:\\Users\Admin\\Documents\\VS-Projects\\Python\\FastAPIServer\\rootCA.pem")
# print(r.json())
print(r1.json())

# print(dict(u1))
# print(bcrypt.gensalt())
# print(hashlib.sha256("Aa123".encode('utf-8')).hexdigest())
# print(bcrypt.hashpw(password="Aa123".encode('utf-8'),salt= '$2b$12$wlKXMWkeMGDSjP7OB6/6ee'.encode('utf-8')))