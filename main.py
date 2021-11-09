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
