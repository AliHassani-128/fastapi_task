from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import hashlib
from jose import jwt
from starlette import status
from starlette.responses import Response

import models
from models import User
from utils import check_username, check_password


app = FastAPI()
db = models.db


@app.get('/')
def home():
    return {'Homepage': 'hello world'}


def login(username, password):
    """
    for authenticate users and check user in database

    """

    user = db.users.find_one({'username': username})
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if not hashed_password == user['password']:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")

    return user


@app.post('/api/auth/register/')
async def sign_up(user: User, response: Response):
    """
    async function for register new user with unique username and password

    """

    if db.users.find_one({'username': user.username}):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'user with this username already exists!'}

    check_username(user.username)
    check_password(user.password)

    hashed_password = hashlib.sha256(user.password.encode('utf-8')).hexdigest()
    user.password = hashed_password
    db.users.insert_one(user.dict(by_alias=True))
    return {'user': user}
