from starlette import status
from starlette.responses import Response
from passlib.context import CryptContext

from main import db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def check_username(username):
    response = Response()
    if not username.isalpha():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'username must be alphabetical characters'}, status.HTTP_400_BAD_REQUEST

    elif len(username) < 4 or len(username) > 32:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'length of user name must be between 4,32'}


def check_password(password):
    response = Response()
    if len(password) < 8:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'length of password must be more than 8 char'}

    if not password.isalnum():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'password should contain number and alphabetical characters'}


def check_national_code(national_code):
    response = Response()
    user = db.users.find_one({'national_code': national_code})
    if user:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'user with this national code has exists!'}
    if len(national_code) < 10:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'length of national code must be 10 char'}
    if not national_code.isdigit():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'national code must be digits!'}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)
