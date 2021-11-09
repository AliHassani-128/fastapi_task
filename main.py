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


def create_access_token(data: dict):
    """
    function that get a user's username and make a token 
    with 15 minutes expire date
    """

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, 'My_secret_key')
    return encoded_jwt


@app.post('/api/auth/api_key/')
async def api_key(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    an async api that check authentication of user 
    and response an access token for 15 minutes

    """

    user = login(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(
        data={"sub": user['username']}
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/auth/me")
async def current_users():

    """
    an async api for show all user's information in the database

    """

    users = [User(**user) for user in db.users.find()]
    return {'users': users}


@app.put('/api/users/reset_password/')
async def reset_password(user: User, response: Response):
    """
    an async api for change an user old password to new password

    """

    find_user = db.users.find_one({'username': user.username})
    if not find_user:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'User with this username does not exists!'}

    check_password(user.password)

    hashed_password = hashlib.sha256(user.password.encode('utf-8')).hexdigest()
    db.users.update({'username': user.username}, {
                    '$set': {'password': hashed_password}})

    return {'success': 'password has changed successfully'}
