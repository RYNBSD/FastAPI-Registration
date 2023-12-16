from typing import LiteralString
from fastapi import FastAPI, Body, Header, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
import time
import math

app = FastAPI()

class User(BaseModel):
    name: str
    email: EmailStr
    password: str

users: list[User] = []
SECRET: LiteralString = "secret"

def hash(password: str) -> str:
    return bcrypt.hashpw(str.encode(password), bcrypt.gensalt(12)).decode()

def compare(password: str, hash: str) -> str:
    return bcrypt.checkpw(str.encode(password), str.encode(hash))

@app.post("/sign-in", status_code=status.HTTP_200_OK, tags=["register"])
async def signIn(email: EmailStr = Body(...), password: str = Body(...)):
    user: User = {
        "name": "",
        "email": "",
        "password": ""
    }

    for u in users:
        if u["email"] == email and compare(password, u["password"]):
            user = u
            break

    token = jwt.encode({
        "email": email,
        "exp": int(math.floor(time.time() + 60 * 30))
    }, SECRET, algorithm="HS256")

    return JSONResponse({
        "success": True,
        "user": user,
    }, status.HTTP_200_OK, {
        "X-JWT-Token": token
    })

@app.post("/sign-up", status_code=status.HTTP_201_CREATED, tags=["register"])
async def signUp(body: User):
    users.append({
        "name": body.name,
        "email": body.email,
        "password": hash(body.password),
    })
    return JSONResponse({
        "success": True
    }, status.HTTP_201_CREATED)

@app.post("/me", status_code=status.HTTP_200_OK, tags=["register"])
async def me(authorization: str = Header()):
    token = jwt.decode(authorization, SECRET, algorithms=["HS256"])

    if time.time() > token["exp"]:
        return JSONResponse({
            "success": False,
        }, status.HTTP_401_UNAUTHORIZED)

    email = token["email"]
    user: User = {
        "name": "",
        "email": "",
        "password": ""
    }

    for u in users:
        if u["email"] == email:
            user = u
            break

    return JSONResponse({
        "success": True,
        "user": user
    }, status.HTTP_200_OK)
