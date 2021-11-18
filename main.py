from datetime import datetime, timedelta

from bson import ObjectId
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import hashlib
from jose import jwt, JWTError
from starlette import status
from starlette.responses import Response
from models import User,Token,TokenData,Text,db
from utils import check_username, check_password, verify_password, get_password_hash, check_national_code
from fastapi_pagination import Page,paginate,add_pagination
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

SECRET_KEY = 'My_secret_key'


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


def authenticate_user(username: str, password: str):
    user = db.users.find_one({'username':username})
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.users.find_one({'username':token_data.username})
    if user is None:
        raise credentials_exception
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
    check_national_code(user.national_code)

    hashed_password = get_password_hash(user.password)
    user.password = hashed_password

    db.users.insert_one({'username':user.username,'password':user.password,'national_code':user.national_code})
    return {'user': user}


@app.put('/api/auth/edit-profile/')
def edit_profile(response : Response,username:str=None,national_code:str=None,user:User=Depends(get_current_user)):

        if username:
            check_username(username)
            if db.users.find_one({'username':username}):
                response.status_code = status.HTTP_400_BAD_REQUEST
                return {'error':'user with this username has exists!'}
            db.users.update({'username':user['username']},{'$set':{'username':username}})
        if national_code:
            check_national_code(national_code)
            if db.users.find_one({'national_code':national_code}):
                db.users.update({'username':user['username']},{'$set':{'national_code':national_code}})
            else:
                return {'error':'user with this national code not found'}
        return {'success':'successfully edit profile'}



@app.post('/api/text/add/')
def add_text(text:str,user:User=Depends(get_current_user)):
    db.text.insert_one({'text':text,'writer':user})
    return {'success':'successfully add one text'}




@app.delete('/api/text/delete/')
def delete_text(id:str,user:User= Depends(get_current_user)):
    db.text.delete_one({'_id':ObjectId(id),'writer':user})
    return {'success':'successfully delete that text'}

@app.put('/api/text/update/')
def update_text(id:str,text:str,user:User=Depends(get_current_user)):
    db.text.update({'_id':ObjectId(id),'writer':user},{'$set':{'text':text}})
    return {'success':'successfully edited'}


@app.get('/api/text/find/',response_model=Page[Text])
def find_text(user:User=Depends(get_current_user)):
    texts = [Text(**text) for text in db.text.find({'writer':user})]
    return paginate(texts)


add_pagination(app)




@app.post("/token", response_model=Token)
async def login_for_get_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user( form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user['username']}
    )
    return {"access_token": access_token, "token_type": "bearer"}


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


@app.get("/api/auth/me",response_model=User)
async def current_user(current_user: User = Depends(get_current_user)):

    """
    an async api for show all user's information in the database

    """

    return current_user


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

    hashed_password = get_password_hash(user.password)
    db.users.update({'username': user.username}, {
                    '$set': {'password': hashed_password}})

    return {'success': 'password has changed successfully'}
